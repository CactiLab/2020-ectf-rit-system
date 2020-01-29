#include <stdint.h>
#include <stdbool.h>

//see memops.c for implementation
/*
returns buf.
*/
void* memset(void* buf, int c, size_t n);
/*
returns dest.
src and dest MAY NOT overlap.
*/
void* memcpy(void* dest, const void* src, size_t n);
/*
returns dest.
src and dest MAY overlap.
*/
void* memmove(void* dest, const void* src, size_t n);
/*
returns:
    + if s1>s2
    0 if s1==s2
    - if s1<s2
*/
int memcmp(const void* s1, const void* s2, size_t n);
/*
copies memory from fpga-only memory to a shared memory section the arm processor can access.
*/
void* copyfromlocal(void* arm_dest, const void* fpga_src, size_t n);
/*
copies memory from shared arm-accessible space to fpga-only ram.
*/
void* copytolocal(void* fpga_dest, const void* arm_src, size_t n);
#ifndef offsetof
#define offsetof(st, m) ((size_t)&(((st *)0)->m))
#endif

//from constants.h mitre file:
#define MAX_SONG_SZ (1<<25) //33554432 == 32 mib (more than system ram lol)

#define PKEY_SIZE 32 //see: eddsa keygen
#define UNAME_SIZE 16 //see: ectf requirements (it is actually 15, but each name is nul-padded to 16 for obvious reasons)
#define SALT_SIZE 16 //see: common sense
#define PIN_SIZE 64 //see: ectf requirements

#define ARGON2_THREADS 1
#define ARGON2_LANES 1
#define INVALID_UID -1
#define PROVISIONED_USERS 1 //TODO: take this from secrets.h
#define MAX_SHARED_USERS MAX_USERS //see: ectf requirements, 3.3.5
#define MAX_USERS 64

#define AVAILABLE_SOC_MEMORY 0x100000 //1mib, soc has 2.5, so we only use some of it.

#define EDDSA_SECRET_SIZE 32 //I think it may actually be 64, but it looks like 1/2 of that is the "random" number generated and 1/2 the public key, so who knows?
#define EDDSA_PUBLIC_SIZE 32
#define EDDSA_SIG_SIZE /*?maybe?*/ 64 //I think

#define MAX_REGIONS 32
#define INVALID_RID -1

enum mipod_ops {
    MIPOD_LOGIN=0,
    MIPOD_LOGOUT,
    MIPOD_PLAY,
    MIPOD_PAUSE,

    MIPOD_RESUME,
    MIPOD_STOP,
    MIPOD_RESTART,
    MIPOD_QUERY,

    MIPOD_FORWARD,
    MIPOD_REWIND,
    MIPOD_DIGITAL,
    MIPOD_SHARE=11
};

struct drm_header { //sizeof() = 1248
    uint8_t song_id[16]; //size should be macroized. a per-song unique ID.
    char owner[UNAME_SIZE]; //the owner's name.
    uint32_t regions[MAX_REGIONS]; //this is a bit on the large size, but disk is cheap so who cares
    /*
    this depends on formatting and memory availability:
    uint32_t offset_30s;
    uint32_t nr_segments;
    uint32_t total_size;
    etc etc
    */
    uint8_t mp_sig[EDDSA_SIG_SIZE]; //a signature (using the mipod private key) for all preceeding data
    char shared_users[UNAME_SIZE][MAX_SHARED_USERS]; //users that the owner has shared the song with.
    uint8_t owner_sig[EDDSA_SIG_SIZE]; //a signature (using the owner's private key) for all preceeding data. resets whenever new user is shared with.
};

/*
checks to see if the shared user entry at <idx_> is in use.
*/
#define CURRENT_DRM_SHARED_EMPTY_SLOT(idx_) (current_song_header.shared_users[idx][0] == '0')

struct mipod_login_data {
    char name[UNAME_SIZE]; //the username of the requested user
    uint8_t pin[PIN_SIZE]; //the entered pin of the requested user
    //no song for this one
};

struct mipod_play_data {
    struct drm_header drm; //this is the file header.
    uint8_t filedata[]; //this is the encrypted and signed song data.
};

struct mipod_query_data {
    uint32_t rids[MAX_REGIONS]; //holds all valid region IDS. the actual region strings should be stored client-side.
    char users_list[UNAME_SIZE][MAX_USERS]; //holds all valid users.
    /*
    Initial boot output :
        mP> Regions: USA, Canada, Mexico\r\n` `mP> Authorized users: alice, bob, charlie, donna\r\n
    Song Query (do in arm mipod, since it can actually just print this mostly verbatim from drm_header structs):
        `mP> Regions: USA, Canada, Mexico\r\n` `mP> Owner: alice\r\n` `mP> Authorized users: bob, charlie, donna\r\n` 
    song querying should be done client-side, since all that data is stored plaintext in the song header.
    */
};

struct mipod_digital_data {
    uint32_t wav_size; //OUT: the used size. will always be <= the file size.
    struct drm_header drm;
    uint8_t filedata[]; //on input, the file that we want to write out. on output, the raw WAV file.
};

struct mipod_share_data {
    char target_name[UNAME_SIZE];
    struct drm_header drm;
    uint8_t filedata[]; //the file to share into.
};

struct mipod_buffer {
    uint32_t operation; //IN, the operation id from enum mipod_ops
    uint32_t status; //OUT, the completion status of the command
    union {
        struct mipod_login_data login_data;
        struct mipod_play_data play_data;
        struct mipod_query_data query_data;
        struct mipod_digital_data digital_data;
        struct mipod_share_data share_data;
    };
};

static uint8_t pin_buffer[PIN_SIZE]; //used for the current pin being tested.
static uint8_t dsa_key_buffer[EDDSA_SECRET_SIZE]; //used for the current user's private key.
static uint32_t current_uid = INVALID_UID;
//todo: use ?????
static struct drm_header current_song_header;
static bool own_current_song;
static bool shared_current_song;

static const mipod_pubkey[EDDSA_PUBLIC_SIZE]; //align this, should also be in secrets.h

static const struct mipod_buffer* mipod_in; //this ends up as a constant address
static volatile bool working = false; //use this in the interrupt handler to avoid preemption race conditions
static volatile bool playing = false; //use this to ensure commands (like pause/etc) are valid only at the correct time.
static volatile bool paused = false; //see above
#define start_working() working=true
#define stop_working() working=false

#ifdef __GNUC__ //using inline asm ensures that the memset calls won't be optimized away.
#define clear_buffer(buf_) do{ memset(buf_,0,sizeof(buf_)); __asm__(""); }while(0)
#define clear_obj(obj_) do{ memset(&(obj_),0,sizeof(obj_); __asm__(""); }while(0)
#else
#define clear_buffer(buf_) memset(buf_,0,sizeof(buf_))
#define clear_obj(obj_) memset(&(obj_),0,sizeof(obj_))
#endif

struct user {
    char name[UNAME_SIZE]; //the username. this is used to check song owners/shared withs.
    size_t argon_itr; //the iterations to use in the argon-2 algorithm (t_cost).
    //size_t argon_bytes; //the amount of memory, in bytes, to feed to argon2 (m_cost).
    uint8_t argon_salt[SALT_SIZE]; //the salt to pass to the argon2 function.
    uint8_t kpublic[PKEY_SIZE]; //the user's public key
}; //these should be set as const in the secrets header file.

/*
given that we have to chunk the music data to prevent TOCTOU issues, the mechanism is as follows:
store a PARTIAL hash (ie don't finalize) of the file header after everything confirms validity.
each chunk should start with that section of the hash, then update it with the current message buffer and check that
signature.
*/

#ifdef _MSC_VER //TODO: all of it 
#pragma region regions
#endif

/*
check to see if the region rid is provisioned for the player
returns true/false for success/fail
*/
static bool valid_region(uint32_t rid) {
    return false;
}

#ifdef _MSC_VER
#pragma endregion 
#endif

#ifdef _MSC_VER //TODO: all of it, plus some libsodium implementations
#pragma region crypto_sign
#endif // _MSC_VER

/*
when using libsodium:
the actual "secret" part of the secret key is the first 32 bytes (what we derive)
the second 32 is the public key

passing it to libsodium would just require combining the two in a local buffer
the message signatures algorithms do have the message hashed in them, so we just have to call sign() and verify()

the sign/verify detached ones are what we want. 
we also have to partially modify them so that they can take a prefix (adding song id + segment index to segments)
*/

/*
verify a data signature using the MIPOD public key.
returns true if it is valid.
data layout looks like:
[....data....][signature]
^-data_start  ^-sig_offset
*/
bool verify_mp_blocksig(void* data_start, size_t sig_offset) {
    return false;
}

/*
verify a data signature using the USER <uid> public key.
returns true if it is valid.
data layout looks like:
[....data....][signature]
^-data_start  ^-sig_offset
*/
bool verify_user_blocksig(void* data_start, size_t sig_offset, uint32_t uid) {
    void* owner_key = get_user_pubkey(uid);
    return false;
}

/*
sign data using the CURRENT USER's private key.
returns true on success.
data layout looks like:
[....data....][signature]
^-data_start  ^-sig_offset
*/
bool sign_user_block(void* data_start, size_t sig_offset) {
    return false;
}

#ifdef _MSC_VER
#pragma endregion
#endif // _MSC_VER

#ifdef _MSC_VER //TODO: all of it
#pragma region user_ops
#endif // _MSC_VER

static uint32_t get_uid_by_name(char username[UNAME_SIZE]) {
    char unlocal[UNAME_SIZE];
    memcpy(unlocal, username, UNAME_SIZE);
    char c = unlocal[0];
    size_t i = 0;
    for (; i < UNAME_SIZE && c; ++i, c = unlocal[i]) { //must be a-zA-Z characters
        if (!('a' <= c && 'z' >= c) || !('A' <= c && 'Z' >= c))
            return INVALID_UID;
    }
    for (; i < UNAME_SIZE; ++i) { //must be nul-padded
        if (unlocal[i])
            return INVALID_UID;
    }
    /*
    for user in USER_LIST, if user.name==unlocal, return offset in USER_LIST
    */
    //TODO: THIS
#error finish this
    return INVALID_UID;
}

/*
perform the argon2 hash on the user pin
uid is the user to do so on. IDK if uid is actually something that we will use.
*/
void gen_user_secret(uint32_t uid) {
    //TODO: ?scrypt//argon2? hash here. should hash into the dsa_key_buffer.
    return;
}

/*
checks to ensure the user is valid (ie their key works on something?)
returns true/false for success/failure
*/
bool valid_user(uint32_t uid) {

}

/*
returns a pointer to the user's public key
*/
static void* get_user_pubkey(uint32_t uid) {
    return NULL;
}

#ifdef _MSC_VER
#pragma endregion
#endif // _MSC_VER

#ifdef _MSC_VER //TODO: verify
#pragma region login
#endif

/*
attempts to logon a user
returns true for success
returns false for failure
*/
bool logon_user(void) {
    char tmpnam[UNAME_SIZE];
    copytolocal(tmpnam, mipod_in->login_data.name, UNAME_SIZE);
    uint32_t user = get_uid_by_name(tmpnam);
    //TODO: use a stack-based pin_buffer

    //ensure there is not a user currently logged in and the user actually exists
    if (current_uid != INVALID_UID || user < PROVISIONED_USERS) {
        return false;
    }

    copytolocal(pin_buffer, mipod_in->login_data.pin, PIN_SIZE); //no TOCTOU here

    //ensure the pin is valid
    for (size_t i = 0; i < PIN_SIZE; ++i) {
        uint8_t b = pin_buffer[i];
        if ((b < '0' || b > '9') && b != 0) { //the pin should be 0-padded if < 64 bytes
            clear_buffer(pin_buffer); //not strictly needed, but better safe than sorry.
            return false; //the pin does not meet standards
        }
    }

    gen_user_secret(user);

    clear_buffer(pin_buffer); //not strictly needed, but better safe than sorry I guess.

    //if everything is fine, go ahead and log them in.
    if (!valid_user(user)) {
        clear_buffer(dsa_key_buffer);
        return false;
    }
    else {
        //the dsa key buffer is already setup (during ?argon2? hashing), so we don't have to do anything here.
        current_uid = user; //ensure everything is good.
        return true; //the user has logged in successfully.
    }
}

/*
logs out the current user and clears their current key.
*/
bool logout_user(void) {
    //memset(dsa_key_buffer, 0, sizeof(dsa_key_buffer));
    if (current_uid != INVALID_UID) {
        clear_buffer(dsa_key_buffer);
        current_uid = INVALID_UID;
        return true;
    }
    else {
        return false;
    }
}

#ifdef _MSC_VER
#pragma endregion
#endif

#ifdef _MSC_VER //TODO: load_segment
#pragma region load_song
#endif // _MSC_VER

#define SONG_OWNER 1 //the song is owned by the current user
#define SONG_SHARED 2 //the song is shared with the current user
#define SONG_BADREGION -1 //the region is not allowed to play the song (a 30s preview should be done instead)
#define SONG_BADUSER -2 //the user is not allowed to play the song (a 30s preview should be done instead)
#define SONG_BADSIG 0 //the song fails signature validation and should not be played.

/*
loads the drm header from arm shared memory into fpga-only bram and ensures that it is valid.
returns one of the SONG_xyz constants
OWNER => the header is valid, and the current user owns it.
SHARED => the song is valid, and the current user has it shared with them.
BADREGION => the song may not be played in the current region, but appears to be a valid song.
BADUSER => the song is neither owned by or shared with the current user, but appears to be a valid song.
BADSIG => the song is invalid and may be discarded.
*/
int32_t load_song_header(struct drm_header * arm_drm) {
    copytolocal(&current_song_header, arm_drm, sizeof(current_song_header));
    void* song_start = ((uint8_t*)arm_drm) + sizeof(*arm_drm);

    //check the edc signature of the mipod application
    if (!verify_mp_blocksig(&current_song_header, offsetof(struct drm_header, mp_sig))) {
        //if its a bad signature, we don't want to play ANY of it, so make sure that we clear it as being loaded.
        clear_obj(current_song_header);
        return SONG_BADSIG;
    }

    //check each region in the song to see if it is a valid region that we can play.
    for (size_t i = 0; i < MAX_REGIONS; ++i) {
        uint32_t _rid = current_song_header.regions[i];
        if (valid_region(_rid))
            goto region_success;
        if (_rid == INVALID_RID)
            break;
    }
    return SONG_BADREGION;
region_success:;

    //check to see if the owner exists
    uint32_t uid = get_uid_by_name(current_song_header.owner);
    if (uid == INVALID_UID)
        return SONG_BADUSER;

    //check the edc signature of the shared section against the owners key
    if (!verify_user_blocksig((uint8_t*)&current_song_header, offsetof(struct drm_header, owner_sig), uid)) {
        clear_obj(current_song_header);
        return SONG_BADSIG;
    }

    //check to see if we own the current song
    if (uid == current_uid) {
        own_current_song = true;
        return SONG_OWNER;
    }

    //check to see if we have the song shared with us
    for (size_t i = 0; i < MAX_SHARED_USERS; ++i) {
        uid = get_uid_by_name(current_song_header.shared_users[i*UNAME_SIZE]); //no, ms, we cannot read 1088 bytes here...
        if (uid == INVALID_UID)
            break;
        if (uid == current_uid)
            return SONG_SHARED;
    }

    //the song is total valid, but the user isn't allowed to play it
    return SONG_BADUSER;
}

/*
unloads the current song drm header
*/
void unload_song_header(void) {
    clear_obj(current_song_header);
}

/*
loads a segment of the current song from arm shared memory to fpga memory and ensures it is valid.
segidx is the index in the file of the loaded segment (ie the 5th segment would have segidx==5).
the function currently assumes a static buffer somewhere (either defined in the file or a reserved hardware block)
rather than one being passed in.
*/
bool load_song_segment(void* arm_start, size_t segsize, uint32_t segidx) {
    void* localblock; //TODO: get this pointed somewhere lol
    /*
    copy the block to bram
    ensure that it is prepended (?or appended maybe?) with the correct song ID and segment index.
    check the signature, if that passes return true.
    if it fails, return false (and clear the memory)?
    */
    return false;
}

/*
unloads the currently loaded song segment of size <size>
currently a noop.
*/
void unload_song_segment(size_t size) {
    return;
}

#ifdef _MSC_VER
#pragma endregion
#endif // _MSC_VER

#ifdef _MSC_VER //TODO: all of it lol, though this should be fairly similar to the reference implementation.
#pragma region play_song
#endif // _MSC_VER

/*
decrypt and play the currently loaded song segment in bram.
*/
bool decrypt_play_segment(size_t size) {
    return false;
}

bool play_song(void) {
    /*
    load the header
    assuming that passes, load each segment,
    then decrypt and play that segment inside bram.
    unload the song.
    every so often we should poll for state changes (pause, stop, restart, etc) and change based on those
    */
}

#ifdef _MSC_VER
#pragma endregion
#endif // _MSC_VER

#ifdef _MSC_VER //TODO: all of it
#pragma region startup_query
#endif // _MSC_VER

bool startup_query(void) {
    return false;
}

#ifdef _MSC_VER
#pragma endregion
#endif // _MSC_VER

#ifdef _MSC_VER //TODO: all of it
#pragma region write_dout
#endif // _MSC_VER

bool digitize_song(void) {
    /*
    load header
    load segment
    decrypt segment
    write decrypted segment back to shm buffer
    load next segment
    reapeat ad infinitum
    */
}

#ifdef _MSC_VER
#pragma endregion
#endif // _MSC_VER

#ifdef _MSC_VER //TODO: verify
#pragma region sharing_is_caring
#endif // _MSC_VER

/*
note: assumes that all possible users will exist on the local device (ie no cross-device song sharing, those users will be overwritten).
*/
bool share_song(void) {
    char target[UNAME_SIZE];
    copytolocal(target, mipod_in->share_data.target_name, UNAME_SIZE);
    bool rcode = false;

    //make sure it is a valid song that we own
    int32_t res = load_song_header(&mipod_in->share_data.drm);
    if (res != SONG_OWNER)
        goto fail;

    //make sure the song has space for another user.
    size_t open = 0;
    uint32_t targetuid = INVALID_UID;
    for (; open < MAX_SHARED_USERS; ++open) {
        if ((targetuid = get_uid_by_name(current_song_header.shared_users[open])) == INVALID_UID)
            //if the first byte is 0 then there is no user and we are good.
            goto shared_space_ok;
    }
    //no space left for sharing, all the users are OK.
    goto fail;
shared_space_ok:;

    //add the target to the shared users table
    memcpy(current_song_header.shared_users[open], target, UNAME_SIZE);

    //sign it with the owner's key and send it back to the caller
    sign_user_block(&current_song_header, offsetof(struct drm_header, owner_sig));
    copyfromlocal(&mipod_in->share_data.drm, &current_song_header, sizeof(current_song_header));

    //nothing else to do, so we are fine
    rcode = true;

fail:;
    unload_song_header();
    return rcode;
}

#ifdef _MSC_VER
#pragma endregion
#endif // _MSC_VER

#ifdef _MSC_VER //pause, resume, stop, restart, forward, rewind. requires play song stuff to be done first.
#pragma region playing_music_ops
#endif // _MSC_VER

bool pause_song(void) {

}

bool resume_song(void) {

}

bool stop_song(void) {

}

bool restart_song(void) {

}

bool forward_song(void) {
    return false;
}

bool rewind_song(void) {
    return false;
}

#ifdef _MSC_VER
#pragma endregion 
#endif // _MSC_VER





/*
apis:
copy_song_localmem <- needed to avoid TOCTOU issues. Note: because on-chip memory is limited to (at most) 2.5 mb, this may need to be chunked.
get_user_key <- PBKDF2(SHA512(username,pin)) <- convert to EDDSA key
get_song_hashes <- compute file header (data block with owner, regions, etc) and encrypted music section hash. compute hash with trailer section.
    returns data in two buffers (first is checked against mipod key, second (shared) checked against user key)
decrypt_play_song <- decrypt and play the song in-place. each sha-512 hash is 64 bytes (I don't actually know off-the-cuff what dsa size is)
    should load a section of the song into local memory, check its signature. if it matches, decrypt the song section and play it.
check_song_signature <- use the computed song hashes to ensure its signature matches.
    *if songs must be chunked, the signatures should be stored in the header along with the number/offsets/etc of chunks
*/

