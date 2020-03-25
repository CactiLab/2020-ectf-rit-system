// #include <stdint.h>
#include <stdbool.h>

#include "secrets.h"
#include "constants.h"
#include "memops.h"
#include "pbkdf2.h"
#include "pbkdf2-hmac-sha512.h"

#include "xdecrypt.h"

#include "xparameters.h"
#include "platform.h"
#include "xstatus.h"
#include "xaxidma.h"
#include "xil_mem.h"
#include "util.h"
#include "xintc.h"
#include "sha512.h"

//HW global state stuff
static XDecrypt myDecrypt;
static XAxiDma sAxiDma;

#ifndef offsetof
#define offsetof(st, m) ((size_t)&(((st *)0)->m))
#endif
#ifndef min
#define min(a,b) (((a)<(b))?(a):(b))
#endif // !min
#ifndef max
#define max(a,b) (((a)>(b))?(a):(b))
#endif // !max

enum mipod_ops {
    MIPOD_PLAY=0,
    MIPOD_PAUSE,
    MIPOD_RESUME,
    MIPOD_STOP,
    MIPOD_RESTART,
    MIPOD_FORWARD,
    MIPOD_REWIND,

    MIPOD_LOGIN,
    MIPOD_LOGOUT,

    MIPOD_QUERY,
    MIPOD_QUERY_SONG,
    MIPOD_DIGITAL,
    MIPOD_SHARE
};

enum mipod_state {
    STATE_NONE=0, //set by the client application
    STATE_WORKING, //set by the client application
    STATE_SUCCESS, //indicates an operation has completed successfully
    STATE_FAILED, //indicates an operation has failed
    STATE_PLAYING //indicates that the firmware has started playing audio
};

typedef struct __attribute__((__packed__)) {
    //riff header
    char chunkID[4]; //"RIFF"
    uint32_t chunk_size; //size of the rest of the header + any data ie rest of file
    char format[4]; //"WAVE"
    //wav format subchunk
    char subchunk1ID[4]; //"fmt "
    uint32_t subchunk1_size; //should be 16 for PCM
    uint16_t audio_fmt; //should be 1 for PCM
    uint16_t n_channels; //mono=1, stereo=2, I doubt we care about others
    uint32_t samplerate; //eg 44.1 khz
    uint32_t byterate; // == samplerate * n_channels * bps/8
    uint16_t blk_align; // == n_channels * bps/8
    uint16_t bits_per_sample; //bits per sample (usually 8 or 16)
    //wav data header
    char subchunk2ID[4]; //"data"
    uint32_t subchunk2_size; //number of data bytes
    //uint8_t data[]; //the actual song
} wav_header;

#define PCM_SUBCH1_SIZE 16 //subchunk1_size for PCM audio
#define AUDIO_FMT_PCM 1 //audio_fmts

#define SONGID_LEN 16

typedef struct __attribute__((__packed__)) { //sizeof() = 1368
    uint8_t song_id[SONGID_LEN]; //size should be macroized. a per-song unique ID.
    char owner[UNAME_SIZE]; //the owner's name.
    uint32_t regions[MAX_SHARED_REGIONS]; //this is a bit on the large size, but disk is cheap so who cares
    //song metadata
    uint32_t len_250ms; //the length, in bytes, that playing 250 milliseconds of audio will take. (the polling interval while playing).
    uint32_t nr_segments; //the number of segments in the song
    uint32_t first_segment_size; //the size of the first song segment (which may not be the full SEGMENT_BUF_SIZE), INcluding trailer.
    wav_header wavdata;
    //validation and sharing
    uint8_t mp_sig[HMAC_SIG_SIZE]; //a signature (using the mipod private key) for all preceeding data
    char shared_users[MAX_SHARED_USERS][UNAME_SIZE]; //users that the owner has shared the song with.
    uint8_t owner_sig[HMAC_SIG_SIZE]; //a signature (using the owner's private key) for all preceeding data. resets whenever new user is shared with.
} drm_header;

#define SONGLEN_30S (current_song_header.len_250ms * 4 * 30)
#define SONGLEN_5S (current_song_header.len_250ms * 4 * 5)
#define SONGLEN_FULL ((current_song_header.nr_segments-1 * SEGMENT_SONG_SIZE)+current_song_header.last_segment_size)

struct segment_trailer {
    uint8_t id[SONGID_LEN]; //16
    uint32_t idx;           //4
    uint32_t next_segment_size; //4
    uint8_t sig[HMAC_SIG_SIZE]; //64
    char _pad_[40]; //do not use this. for cryptographic padding purposes only. //40
};

struct {
    char a[0-!(sizeof(struct segment_trailer) == 128 && CIPHER_BLOCKSIZE == 64)]; //if the segment trailer requirements fail, this will break.
};

/*
checks to see if the shared user entry at <idx_> is in use.
*/
#define CURRENT_DRM_SHARED_EMPTY_SLOT(idx_) (current_song_header.shared_users[idx_][0] == '\0')

typedef struct {
    char name[UNAME_SIZE]; //the username of the requested user
    uint8_t pin[PIN_SIZE]; //the entered pin of the requested user
    uint32_t uid;
    char logged_in;  // the status of the user
    //no song for this one
} mipod_login_data;

typedef struct __attribute__((__packed__)) {
    drm_header drm; //this is the file header.
    uint8_t filedata[]; //this is the encrypted and signed song data.
} mipod_play_data;

typedef struct {
    char regions[MAX_SHARED_REGIONS * REGION_NAME_SZ];
    char song_regions[MAX_SHARED_REGIONS * REGION_NAME_SZ];
    // uint32_t rids[MAX_QUERY_REGIONS]; //holds all valid region IDS. the actual region strings should be stored client-side.
    char users_list[TOTAL_USERS][UNAME_SIZE]; //holds all valid users.
    /*
    Initial boot output :
        mP> Regions: USA, Canada, Mexico\r\n` `mP> Authorized users: alice, bob, charlie, donna\r\n
    Song Query (do in arm mipod, since it can actually just print this mostly verbatim from drm_header structs):
        `mP> Regions: USA, Canada, Mexico\r\n` `mP> Owner: alice\r\n` `mP> Authorized users: bob, charlie, donna\r\n` 
    song querying should be done client-side, since all that data is stored plaintext in the song header.
    */
} mipod_query_data;

typedef struct __attribute__((__packed__)) {
    uint32_t wav_size; //OUT: the used size. will always be <= the file size.
    // drm_header drm;
    // uint8_t filedata[]; //on input, the file that we want to write out. on output, the raw WAV file.
    mipod_play_data play_data;
} mipod_digital_data ;

typedef struct __attribute__((__packed__)) {
    char target_name[UNAME_SIZE];
    drm_header drm; //we don't actually need anything but the file header for this.
} mipod_share_data;

typedef volatile struct __attribute__((__packed__)) {
    uint32_t operation; //IN, the operation id from enum mipod_ops
    uint32_t status; //OUT, the completion status of the command. DO NOT read this field.
    union {
        mipod_login_data login_data;
        // struct mipod_play_data play_data;
        mipod_query_data query_data;
        mipod_share_data share_data;
        mipod_digital_data digital_data;
        char buf[MAX_SONG_SZ];
    };
}mipod_buffer;

//the following should ALL be in fpga-only memory. idk what the specifics of the load process are (ie is our .data in dram or soc?)

static uint8_t pin_buffer[PIN_SIZE]; //used for the current pin being tested.
static uint32_t current_uid = INVALID_UID;

static drm_header current_song_header;
volatile mipod_buffer *mipod_in = (mipod_buffer*)SHARED_DDR_BASE;  //this ends up as a constant address

#define set_status_success() do{mipod_in->status=STATE_SUCCESS;}while(0)
#define set_status_failed() do{mipod_in->status=STATE_FAILED;}while(0)
static uint8_t segment_buffer[SEGMENT_BUF_SIZE]; //the memory buffer that we copy our data to (either constant address or array, idk yet)

enum PLAY_OPS {
    PLAYER_PLAY=0,
    PLAYER_PAUSE,
    PLAYER_RESUME,
    PLAYER_STOP,
    PLAYER_RESTART,
#if 0
    PLAYER_FORWARD,
    PLAYER_REWIND,
    PLAYER_FORWARD_PAUSE,
    PLAYER_REWIND_PAUSE,
#endif
    PLAYER_NONE
};

static bool own_current_song = false;
static bool shared_current_song = false;
static volatile bool working = false; //use this in the interrupt handler to avoid preemption race conditions (alone with interrupt en/dis)
static volatile uint8_t music_op = PLAYER_NONE; //the current operation the music player should perform (if it is in-use)
#define start_working() working=true
#define stop_working() working=false

#ifdef __GNUC__ //using inline asm ensures that the memset calls won't be optimized away.
#define clear_buffer(buf_) do{ memzero((buf_),sizeof(buf_)); __asm__ volatile ("" ::: "memory"); }while(0)
#define clear_obj(obj_) do{ memzero(&(obj_),sizeof(obj_)); __asm__ volatile ("" ::: "memory"); }while(0)
#else
#define clear_buffer(buf_) memzero(buf_,sizeof(buf_))
#define clear_obj(obj_) memzero(&(obj_),sizeof(obj_))
#endif

#ifdef __GNUC__
#define noreturn __attribute__((noreturn))
#else
#define noreturn //__declspec(noreturn)
#endif // __GNUC__

#ifdef USE_TAMPER
noreturn void TAMPER(void) {
#pragma message("need to write to the PL reset register and reset the system")
    // *(uint32_t*)ADDRESS = 1; // <- resets the PL
    __builtin_unreachable();
}
#else
#define TAMPER() ((void)0)
#endif // USE_TAMPER


#ifdef _MSC_VER
#pragma region interrupt_handler
#endif // _MSC_VER

#define disable_interrupts() microblaze_disable_interrupts()
#define enable_interrupts() microblaze_enable_interrupts()

/*
checks to see if the requested command is OK to execute right now.
DOES NOT mean that the command isn't malicious or invalid, just that it isn't being requested at a wildly invalid time.
*/
static bool is_command_ok(uint32_t c) {
    switch (c) {
    case(MIPOD_PLAY): //there can't be a song currently playing (don't have to login though I don't think)
        return music_op == PLAYER_NONE;
    case(MIPOD_PAUSE):
    case(MIPOD_RESUME):
    case(MIPOD_STOP):
#if 0
    case(MIPOD_RESTART):
    case(MIPOD_FORWARD):
#endif
    case(MIPOD_REWIND): //these can't run unless a song is playing or paused.
        return music_op <= PLAYER_PAUSE;
    case(MIPOD_LOGIN): //there can't be anyone logged in already.
        return current_uid == INVALID_UID;
    case(MIPOD_LOGOUT): //there must be a user logged in and they can't be playing a song
    case(MIPOD_QUERY): //this is run @ application startup, there isn't really a good way to check for validity, but there shouldn't be anyone logged in or playing music, so it holds.
        return (current_uid != INVALID_UID && music_op == PLAYER_NONE);
    case(MIPOD_DIGITAL): //can't do it while we are playing a song.
        return music_op == PLAYER_NONE;
    case(MIPOD_SHARE): //must be logged-in and not playing music.
        return (current_uid != INVALID_UID && music_op == PLAYER_NONE);
    default: return false;
    }
}

static void pause_song(void);
static void resume_song(void);
static void stop_song(void);
static void restart_song(void);
static void forward_song(void);
static void rewind_song(void);

static bool play_song(void);
static bool login_user(void);
static bool logout_user(void);
static bool startup_query(void);
static bool query_song(void);
static bool digitize_song(void);
static bool share_song(void);

//need to put special attributes on here
void gpio_entry() {
    // mb_printf("startup interrupt handler...\r\n");
    disable_interrupts();
    
    /*
    get operation
    if ! operation_allowed, set failed && exit
    else, run operation
    */
    // uint32_t op = mipod_in->operation;
    // if (!is_command_ok(op)) {
    //     mb_printf("wrong operation\r\n");
    //     goto fail;
    // }
    // mb_printf("operation id is: %d \r\n", mipod_in->operation);
    bool res = true;
    mipod_in->status = STATE_WORKING;
    switch (mipod_in->operation) {
        case MIPOD_PLAY: mb_printf("startup mipod play\r\n"); res = play_song(); break;
        //case MIPOD_PAUSE: mb_printf("pausing mipod\r\n"); pause_song(); break; //these are voids and handle stuff directly inside themselves.
       // case MIPOD_RESUME: mb_printf("resuming the song\r\n"); resume_song(); break;
       // case MIPOD_STOP: mb_printf("stopping the song\r\n"); stop_song(); return;
       // case MIPOD_RESTART: mb_printf("restarting the song\r\n"); restart_song(); break;
        case MIPOD_FORWARD: mb_printf("forwarding the song\r\n"); forward_song(); break;
        case MIPOD_REWIND: mb_printf("rewinding the song\r\n"); rewind_song(); break;
        case MIPOD_LOGIN: mb_printf("user login\r\n"); res = login_user(); break;
        case MIPOD_LOGOUT: mb_printf("user logout\r\n"); res = logout_user(); break;
        case MIPOD_QUERY: 
            // mb_printf("startup mipod query\r\n");
            res = startup_query(); 
            break;
        case MIPOD_QUERY_SONG:
            res = query_song();
            break;
        case MIPOD_DIGITAL: mb_printf("digital output command\r\n"); res = digitize_song(); break;
        case MIPOD_SHARE: mb_printf("sharing the song\r\n"); res = share_song(); break;
        default: goto fail;
        // default: break;
    }
    if (!res) {
        fail:;
            mipod_in->status = STATE_FAILED;
    }
    else mipod_in->status = STATE_SUCCESS;
    enable_interrupts();
    usleep(500);
}

#ifdef _MSC_VER
#pragma endregion
#endif // _MSC_VER

#ifdef _MSC_VER
#pragma region main
#endif // _MSC_VER

int main() {
    uint32_t status = XST_FAILURE;
    static XIntc InterruptController;

    init_platform();

/*
    //Initialize the AES module

    XDecrypt myDecrypt;
    XDecrypt_Config* myDecrypt_cfg;

    myDecrypt_cfg = XDecrypt_LookupConfig(XPAR_DECRYPT_0_DEVICE_ID);
    if (!myDecrypt_cfg) {
        mb_printf("Error loading configuration for component XDecrypt\r\n");
        return status;
    }

    status = XDecrypt_CfgInitialize(&myDecrypt, myDecrypt_cfg);
    if (status != XST_SUCCESS) {
        mb_printf("Error initializing configuration for component XDecrypt\r\n");
        return status;
    }
    else {
        status = XDecrypt_Initialize(&myDecrypt, XPAR_DECRYPT_0_DEVICE_ID);
        if (status != XST_SUCCESS) {
            mb_printf("Error initializing component XDecrypt\r\n");
            return status;
        }
    }
*/

    mb_printf("Setup our interrupt handler\r\n");
    //Setup our interrupt handler
    microblaze_register_handler((XInterruptHandler)gpio_entry, (void *)0);
    microblaze_enable_interrupts();

    // Initialize the interrupt controller driver so that it is ready to use.
    status = XIntc_Initialize(&InterruptController, XPAR_INTC_0_DEVICE_ID);
    if (status != XST_SUCCESS) {
        mb_printf("Initialize interruption ERROR\r\n");
        return XST_FAILURE;
    }

    // Set up the Interrupt System.
    status = SetUpInterruptSystem(&InterruptController, (XInterruptHandler)gpio_entry);
    if (status != XST_SUCCESS) {
        mb_printf("Setup interruptsystem ERROR\r\n");
        return XST_FAILURE;
    }

    // Configure the DMA
    status = fnConfigDma(&sAxiDma);
    if (status != XST_SUCCESS) {
        mb_printf("DMA configuration ERROR\r\n");
        return XST_FAILURE;
    }

    mipod_in->operation = MIPOD_STOP;

    // clear mipod_buffer channel
    memset((void*)mipod_in, 0, sizeof(mipod_buffer));

    mb_printf("Audio DRM Module has Booted\r\n");

//    static const uint8_t mipod_key[] = "hello";

//    uint8_t sig[HASH_OUTSIZE];

//    hmac((uint8_t *)"hello", "hello", 5, sig);

    // Handle commands forever
    while(1);

    //clear_obj(mipod_in);

    for (;;) mb_sleep(); //we don't do any work in here, so no point in wasting cycles.

    cleanup_platform();
    return 0;
}

#ifdef _MSC_VER
#pragma endregion
#endif // _MSC_VER

#ifdef _MSC_VER
#pragma region wav_info
#endif

//static uint32_t wav_bytes_per_second(const struct wav_header* whdr) {
//    // Bits Per Second (bps) = Sample Rate (Hz) * Word Length (bits) * Channel Count
//    return whdr->samplerate * (whdr->bits_per_sample/8) * whdr->n_channels;
//}

#ifdef _MSC_VER
#pragma endregion
#endif // _MSC_VER

#ifdef _MSC_VER //TODO: verify
#pragma region regions
#endif

/*
check to see if the region rid is provisioned for the player
returns true/false for success/fail
*/
static bool valid_region(uint32_t rid) {
    for (size_t i = 0; i < TOTAL_REGIONS; ++i) 
        if (provisioned_regions[i] == rid)
            return true;
    return false;
}

// looks up the region name corresponding to the rid
static bool rid_to_region_name(char rid, char **region_name, int provisioned_only) {
    for (int i = 0; i < NUM_REGIONS; i++) {
        if (rid == REGION_IDS[i] &&
            (!provisioned_only || valid_region(rid))) {
            *region_name = (char *)REGION_NAMES[i];
            return true;
        }
    }

    mb_printf("Could not find region ID '%d'\r\n", rid);
    *region_name = "<unknown region>";
    return false;
}


// looks up the rid corresponding to the region name
static bool region_name_to_rid(char *region_name, char *rid, int provisioned_only) {
    for (int i = 0; i < NUM_REGIONS; i++) {
        if (!strcmp(region_name, REGION_NAMES[i]) &&
            (!provisioned_only || valid_region(REGION_IDS[i]))) {
            *rid = REGION_IDS[i];
            return true;
        }
    }

    mb_printf("Could not find region name '%s'\r\n", region_name);
    *rid = -1;
    return false;
}

#ifdef _MSC_VER
#pragma endregion 
#endif

#ifdef _MSC_VER //TODO: implement decrypt_segment_data (for play_segment)
#pragma region crypto_sign
#endif // _MSC_VER

/*
verify a data signature using the MIPOD public key.
returns true if it is valid.
data layout looks like:
[....data....][signature]
^-data_start  ^-sig_offset
*/
//verify_mp_blocksig(&current_song_header, offsetof(drm_header, mp_sig)
static bool verify_mp_blocksig(void* data_start, size_t sig_offset) {
    //return !crypto_sign_ed25519_verify_detached((uint8_t*)data_start + sig_offset, data_start, sig_offset, mipod_pubkey);
    uint8_t sig[HASH_OUTSIZE];
//    void *tmp = data_start;
//    size_t offset = sig_offset;
//    unsigned char in[6] = {'h', 'e', 'l', 'l', 'o', 0};
//    uint8_t key[5] = "hello";
//    size_t size = 5;
    memset(sig, 0, HASH_OUTSIZE);
//    crypto_hash_sha512(sig, 5, "hello");

//    mb_printf("sha512 hello: ");
//     for (size_t i = 0; i < HASH_OUTSIZE; i++)
//     {
//         mb_printf("%x ", sig[i]);
//     }
//     mb_printf("\r\n");
//     unsigned char in2[6] = {'h', 'e', 'l', 'l', 'o', 0};
//     memset(sig, 0, HASH_OUTSIZE);
//    SHA512("hello", 5, sig);
//    mb_printf("sha512 hello: ");
//     for (size_t i = 0; i < HASH_OUTSIZE; i++)
//     {
//         mb_printf("%x ", sig[i]);
//     }
//     mb_printf("\r\n");

//     hmac(key, in, size, sig);
//     mb_printf("hmac-sha512 hello: ");
//      for (size_t i = 0; i < HASH_OUTSIZE; i++)
//      {
//          mb_printf("%x ", sig[i]);
//      }
//      mb_printf("\r\n");

     hmac(mipod_key, data_start, sig_offset, sig);
//    mb_printf("hmac_mp_sig: ");
//     for (size_t i = 0; i < HASH_OUTSIZE; i++)
//     {
//         mb_printf("%x ", sig[i]);
//     }
//     mb_printf("\r\n");
    return !memcmp(sig, (uint8_t*)data_start + sig_offset, HASH_OUTSIZE);
}

/*
verify a data signature using the USER <uid> public key.
returns true if it is valid.
data layout looks like:
[....data....][signature]
^-data_start  ^-sig_offset
*/
static bool verify_user_blocksig(void* data_start, size_t sig_offset, uint32_t uid) {
    uint8_t sig[HASH_OUTSIZE];
    // drm_header *tmp = data_start;
    memset(sig, 0, HASH_OUTSIZE);
    // mb_printf("sig: %p\r\n", sig);
    // drm_header *tmp = data_start;
    // mb_printf("uid: %d\r\n", uid);
    // mb_printf("user_hash: ");
    // for (size_t i = 0; i < HASH_OUTSIZE; i++)
    // {
    //     mb_printf("%x ", provisioned_users[uid].hash[i]);
    // }
    // mb_printf("\r\n");

    // mb_printf("sig_offset: %ld\r\n", sig_offset);
    // mb_printf("uid: %d\r\n", uid);
    // mb_printf("data_start: %p", data_start);

    hmac(provisioned_users[uid].hash, data_start, sig_offset, sig);

    // mb_printf("after: %p\r\n", sig);

//    mb_printf("hmac_user_sig: ");
//     for (size_t i = 0; i < HASH_OUTSIZE; i++)
//     {
//         mb_printf("%x ", sig[i]);
//     }
//     mb_printf("\r\n");

    // mb_printf("sig_offset: %ld\r\n", sig_offset);
    // mb_printf("uid: %d\r\n", uid);
    // mb_printf("data_start_owner: %p", data_start);

    // int flag = memcmp(sig, (uint8_t*)data_start + sig_offset, HASH_OUTSIZE);

    // mb_printf("cmp flag: %d\r\n", flag);

    return !memcmp(sig, (uint8_t*)data_start + sig_offset, HASH_OUTSIZE);
}

/*
sign data using the CURRENT USER's private key.
returns true on success.
data layout looks like:
[....data....][signature]
^-data_start  ^-sig_offset
*/
static bool sign_user_block(void* data_start, size_t sig_offset) {
    hmac(provisioned_users[current_uid].hash, data_start, sig_offset, (uint8_t*)data_start + sig_offset);
    return true;
}

/*
decrypts <len> bytes at <start> using the hardware-stored keys.
returns the actual length of the decrypted data (removing padding, for example)
<len> = size of segment, including trailer and padding.
<start> = start of segment.
*/
static size_t decrypt_segment_data(void* start, size_t len) {
//    len -= sizeof(struct segment_trailer);


    //Initialize the AES module

	int status;
    XDecrypt myDecrypt;
    XDecrypt_Config* myDecrypt_cfg;

    myDecrypt_cfg = XDecrypt_LookupConfig(XPAR_DECRYPT_0_DEVICE_ID);
    if (!myDecrypt_cfg) {
        mb_printf("Error loading configuration for component XDecrypt\r\n");
        return status;
    }

    status = XDecrypt_CfgInitialize(&myDecrypt, myDecrypt_cfg);
    if (status != XST_SUCCESS) {
        mb_printf("Error initializing configuration for component XDecrypt\r\n");
        return status;
    }
    else {
        status = XDecrypt_Initialize(&myDecrypt, XPAR_DECRYPT_0_DEVICE_ID);
        if (status != XST_SUCCESS) {
            mb_printf("Error initializing component XDecrypt\r\n");
            return status;
        }
    }


	mb_printf("-- Starting AES hardware test based on FIPS-197 (Appendix B)\n");


    int count = len/16;
    // uint8_t *en_data[count][128] = start;
    uint8_t *tmp;
    
    for (size_t i = 0; i < count; i++)
    {
        int block_offset = i*16;
        int block_start = start + block_offset;
        XDecrypt_Write_CipherText_Bytes(&myDecrypt, 0, block_start, 16); //we can probably make these use words

        XDecrypt_Start(&myDecrypt);

        while (!XDecrypt_IsDone(&myDecrypt));

        XDecrypt_Read_PlainText_Bytes(&myDecrypt, 0, block_start, 16);

        // Transpose back the block


    }

    return len;
}

#ifdef _MSC_VER
#pragma endregion
#endif // _MSC_VER

#ifdef _MSC_VER //TODO: verify
#pragma region user_ops
#endif // _MSC_VER

uint32_t get_uid_by_name(const char username[UNAME_SIZE]) {
    
    char c = username[0];
    size_t i = 0;
    /*
    //make sure the username fits the character constraints
    for (; i < UNAME_SIZE; ++i, c = username[i]) { //must be a-zA-Z characters
        mb_printf(" %c ", c);
        if (!('a' <= c && 'z' >= c) || !('A' <= c && 'Z' >= c))
            break;
            // return INVALID_UID;
    }
    for (; i < UNAME_SIZE; ++i) { //must be nul-padded
        if (username[i])
            return INVALID_UID;
    }
    */
    //check through all the users to see if they match
    for (i = 0; i < TOTAL_USERS; ++i) {
        if (!memcmp(provisioned_users[i].name, username, UNAME_SIZE))
            return i;
    }
    return INVALID_UID;
}

/*
perform the pbkdf2 function on the key and copy it to 
uid is the user to do so on. IDK if uid is actually something that we will use.
returns true/false for if the user is OK or not.
*/
bool gen_check_user_secret(uint32_t uid) {

    uint8_t kb[KDF_OUTSIZE]; //derived key buffer
    pbkdf2_hmac_sha512(kb,KDF_OUTSIZE,pin_buffer,sizeof(pin_buffer),provisioned_users[uid].salt,sizeof(provisioned_users[uid].salt),500);
   // pbkdf2(pin_buffer, sizeof(pin_buffer), provisioned_users[uid].salt, kb); //note: this doesnt use the full output in keypair generation
    clear_buffer(pin_buffer);
    
    return !memcmp(kb, provisioned_users[uid].hash, HASH_OUTSIZE);
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
bool login_user(void) {
    mb_printf("Logined data : %d",mipod_in->login_data.logged_in);
    if(mipod_in->login_data.logged_in){
        mb_printf("Already logged in. Please logout first.\r\n");
        return true;
    }
    else{
        char tmpnam[UNAME_SIZE];
        copytolocal(tmpnam, mipod_in->login_data.name, UNAME_SIZE);
        mb_printf("uname is: %s\r\n", tmpnam);
        uint32_t user = get_uid_by_name(tmpnam);
        mb_printf("uid is: %d\r\n", user);
         
        //TODO: use a stack-based pin_buffer

        //ensure there is not a user currently logged in and the user actually exists
        if (current_uid == INVALID_UID && user == INVALID_UID){
            mb_printf("Invalid user!\r\n");
            return false;
        }

        copytolocal(pin_buffer, mipod_in->login_data.pin, PIN_SIZE); //no TOCTOU here
        // mb_printf("sizeof(pin_buffer): %d", strlen(pin_buffer));

        //if everything is fine, go ahead and log them in.
        if (!gen_check_user_secret(user)) {
            mb_printf("Wrong PIN!\r\n");
            return false;
        }
        else {
            mipod_in->login_data.uid = user;
            mipod_in->login_data.logged_in = 1;
            mb_printf("User %s logged in.\r\n", tmpnam);
            current_uid = user; //ensure everything is good.
            return true; //the user has logged in successfully.
        }
    }
    /*memset((void*)mipod_in->login_data.logged_in, 0, sizeof(uint32_t));
    memset((void*)mipod_in->login_data.name, 0, UNAME_SIZE);
    memset((void*)mipod_in->login_data.pin, 0, PIN_SIZE);
    return false;*/
}

/*
logs out the current user and clears their current key.
*/
bool logout_user(void) {
    if (current_uid != INVALID_UID) {
        current_uid = INVALID_UID;
        mipod_in->login_data.logged_in = 0;
        memset((void*)mipod_in->login_data.name, 0, UNAME_SIZE);
        memset((void*)mipod_in->login_data.pin, 0, PIN_SIZE);
        return true;
    }
    else {
        mb_printf("No user logged in. Please login first.\r\n");
        //something fishy is going on
        return true;
    }
}

#ifdef _MSC_VER
#pragma endregion
#endif

#ifdef _MSC_VER //TODO: ?unload_segment?, verify, ?do sanity checking on wav header?
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
BADSIG => the song is invalid and may be discarded (current_song_header and other state will be cleared).
*/
int32_t load_song_header(drm_header * arm_drm) {
    copytolocal(&current_song_header, arm_drm, sizeof(current_song_header));

    //check the edc signature of the mipod application
    if (!verify_mp_blocksig(&current_song_header, offsetof(drm_header, mp_sig))) {
        //if its a bad signature, we don't want to play ANY of it, so make sure that we clear it as being loaded.
        mb_printf("Invalid song!\r\n");
        clear_obj(current_song_header);
        TAMPER();
        return SONG_BADSIG;
    }

    //check each region in the song to see if it is a valid region that we can play.
    for (size_t i = 0; i < MAX_SHARED_REGIONS; ++i) {
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
    if (uid == INVALID_UID){
        mb_printf("Invalid user! Play 30s.\r\n");
        return SONG_BADUSER;
    }
        
    //check the edc signature of the shared section against the owners key
    if (!verify_user_blocksig(&current_song_header, offsetof(drm_header, owner_sig), uid)) {
        clear_obj(current_song_header);
        mb_printf("User verify faild!\r\n");
        return SONG_BADSIG;
    }

    //check to see if we own the current song
    current_uid = 2;   //the login_user haven't finished, so set the owner id
    if (uid == current_uid) {
        own_current_song = true;
        mb_printf("You are the owner of the song, now starting to play the full song.\r\n");
        return SONG_OWNER;
    }

    //check to see if we have the song shared with us
    for (size_t i = 0; i < MAX_SHARED_USERS; ++i) {
        uid = get_uid_by_name(current_song_header.shared_users[i]);
        if (uid == INVALID_UID)
            break;
        if (uid == current_uid){
            mb_printf("You are shared withe the song, now starting to play the full song.\r\n");
            return SONG_SHARED;
        }        
    }

    //the song is total valid, but the user isn't allowed to play it
    return SONG_BADUSER;
}

/*
unloads the current song drm header, clears the song owners
*/
void unload_song_header(void) {
    clear_obj(current_song_header);
    own_current_song = false;
    shared_current_song = false;
}

/*
loads a segment of the current song from arm shared memory to fpga memory and ensures it is valid.
segidx is the index in the file of the loaded segment (ie the 5th segment would have segidx==5).
the function currently assumes a static buffer somewhere (either defined in the file or a reserved hardware block)
rather than one being passed in.
*/
bool load_song_segment(void* arm_start, size_t segsize, uint32_t segidx) {
    if (segsize > SEGMENT_BUF_SIZE) { //this should be proveable at compile-time
        //idk? die i guess?
        mb_printf("The segment size is invalid.\r\n");
        return *(char*)NULL;
    }

    //load the segment
    copytolocal(segment_buffer, arm_start, segsize);
    size_t sdata_size = segsize - sizeof(struct segment_trailer);
    struct segment_trailer* trailer = (struct segment_trailer*) ((uint8_t*)segment_buffer + sdata_size);

    //if there is an index mismatch or the segment does not belong to the current song, somebody is being naughty
    if (trailer->idx != segidx || memcmp(current_song_header.song_id, trailer->id, SONGID_LEN)) {
        //memzero?
        return false;
    }

    //make sure the segment is something we actually signed and hasn't been swapped around
    if (verify_mp_blocksig(segment_buffer, sdata_size + offsetof(struct segment_trailer, sig))) {
        return true;
    }
    else {
        TAMPER();
        return false;
    }
}

/*
unloads the currently loaded song segment of size <size>
currently a noop.
*/
//void unload_song_segment(size_t size) {
//    return;
//}

#ifdef _MSC_VER
#pragma endregion
#endif // _MSC_VER

#ifdef _MSC_VER //TODO: play_segment_bytes (see fnAudioPlay), forward/rewind, verify
#pragma region play_song
#endif // _MSC_VER

/*
song playing currently depends on the following:
.wav files are able to be separated into chunks based on the time to play them
memory segments contain a multiple of that data size
*/

/*
plays the currently loaded song segment in bram.
*/
void play_segment_bytes(void * start, size_t size) {
    u32 cp_xfil_cnt, * fifo_fill;
    fifo_fill = (u32*)XPAR_FIFO_COUNT_AXI_GPIO_0_BASEADDR;
#if SEGMENT_BUF_SIZE > PCM_DRV_BUFFER_SIZE
#error play assumes each segment will always be smaller than the pcm buffers
#endif
    static u8 last_pcm_buf = 0;
    static bool have_run = false;

    //load the data into the pcm driver buffer
    Xil_MemCpy((void*)(XPAR_MB_DMA_AXI_BRAM_CTRL_0_S_AXI_BASEADDR + (last_pcm_buf ? PCM_DRV_BUFFER_SIZE : 0)), start, size);

    cp_xfil_cnt = size;

    while (cp_xfil_cnt > 0) {

        // polling while loop to wait for DMA to be ready
        // DMA must run first for this to yield the proper state
        // ref system seems to imply this will reset itself to invalid between songs, which seems weird

        while (XAxiDma_Busy(&sAxiDma, XAXIDMA_DMA_TO_DEVICE) && have_run && *fifo_fill < (FIFO_CAP - 32));
        have_run = true;
#pragma message("idk about this....it seems to imply that the dma resets between songs, which seems wrong")

        // do DMA
        u32 dma_cnt = (FIFO_CAP - *fifo_fill > cp_xfil_cnt)
            ? FIFO_CAP - *fifo_fill
            : cp_xfil_cnt;
        fnAudioPlay(sAxiDma, (last_pcm_buf ? PCM_DRV_BUFFER_SIZE : 0), dma_cnt);
        cp_xfil_cnt -= dma_cnt;
    }

    last_pcm_buf ^= 1; //switch buffers each time
    return;
}

#define SEEK_OK 0 //seeking was successful
#define SEEK_FAIL -1 //seeking failed because the song became invalid
#define SEEK_END 1 //seeking forward led to the end of the song
#define SEEK_START 1 //seeking backward led to the start of the song

#if 0

/*
seek forward 5 seconds in the currently loaded song.
returns false if that would cause the song to end (and should be unloaded).
writes the new song offset into curr

curr [in] = current offset into the song
curr [out] = new offset into the song
seg [in] = current offset into loaded segment
seg [out] = new offset into loaded segment
segsz = size of current segment (should this be a pointer?)
idx = current segment index (should this be a pointer?)
*/
static int32_t seek_fwd(size_t * seg, size_t segsz, size_t * curr, uint32_t idx) {
    size_t l = SONGLEN_5S, c = *curr, target = c + l, o = *seg;
    if (target < c) //overflow, end song
        return SEEK_END;
    if (target > segsz) { //go to next segment
        struct segment_trailer * trailer = (uint8_t*)segment_buffer + segsz - sizeof(*trailer);
        do {
            size_t next = trailer->next_segment_size;
            void * start_next = &(mipod_in->digital_data.play_data.filedata[target + idx * sizeof(struct segment_trailer)]);
            if (!load_song_segment(start_next, next, ++idx))
                return SEEK_FAIL;
#error finish this stuff
        } while (0);
    }
    else { //don't have to do anything, stay in this segment
        *seg = o + l;
        *curr = target;
        return SEEK_OK;
    }
}

/*
seek backward 5 seconds in the currently loaded song.
returns false if that would cause the song to restart (which is OK).
writes the new song offset into curr

curr [in] = current offset into the song
curr [out] = new offsent into the song
*/
static bool seek_rev(size_t * curr) {
    size_t l = SONGLEN_5S, c = *curr, target = c - l;
    if (target > c) //underflow, restart
        return false;
}

#endif

 bool play_song(void) {
    /*
    load the header
    assuming that passes, load each segment,
    then decrypt and play that segment inside bram.
    unload the song.
    every so often we should poll for state changes (pause, stop, restart, etc) and change based on those
    */
    size_t offset = 0, bytes_max = 0; //the maximum number of bytes to play in the song, and the total number we have already played.
    // mb_printf("play_song mipod_key: ");
    // for (int i = 0; i < HASH_OUTSIZE; i++)
    // {
    //     mb_printf("%x ", mipod_key[i]);
    // }
    // printf("\r\n");
    
    switch (load_song_header(&mipod_in->digital_data.play_data.drm)) {
    case(SONG_BADUSER):;
    case(SONG_BADREGION):mb_printf("Bad region, play 30s.\r\n"); //we can play 30s, but no more
        bytes_max = SONGLEN_30S;
        mipod_in->status = STATE_PLAYING;
        break;
    case(SONG_BADSIG):;
        unload_song_header();
        mipod_in->status = STATE_FAILED;
        return false;
    case(SONG_OWNER): ;
    case(SONG_SHARED): ; //we can play the full song
        mipod_in->status = STATE_PLAYING;
        break;
#ifdef __GNUC__
    default:__builtin_unreachable();
#endif
    }
    // mipod_in->status = STATE_PLAYING; //no racing here
    enable_interrupts();
restart_playing:;
    mipod_in->status = STATE_PLAYING;
    uint8_t* fseg = &(mipod_in->digital_data.play_data.filedata[0]); //a pointer to the start of the segment to load within the shared memory section
    size_t i = 0;
    size_t segsize = current_song_header.first_segment_size;
    //loop through all the segments in the file, make sure the update size is correct
    for (; i < current_song_header.nr_segments; ++i) {
        if (!load_song_segment(fseg, segsize, i)) {
        	mb_printf("Load song segment failed.\r\n");
            unload_song_header();
            disable_interrupts(); //idk that this is strictly necessary
            return false;
        }
        //prepare to play next segment
        size_t raw = decrypt_segment_data(segment_buffer, segsize - sizeof(struct segment_trailer));
        //for each interval (250 ms right now) in bytes, play the audio and check for state changes.
        if (bytes_max && offset >= bytes_max) { //make sure we arent playing too much audio
            goto unload;
        }
        offset += raw;
        //update our position in the loaded song
        fseg += segsize;
        //get next segment size
        segsize = ((struct segment_trailer*) & (segment_buffer[raw]))->next_segment_size;
        play_segment_bytes(segment_buffer, raw);
        //these *should* be interrupt-safe.
    repoll_music_op:
        switch (music_op) {
        case(PLAYER_PLAY):break; //this is the default, continue playing the song
        case(PLAYER_PAUSE): //stop playing, wait for <!play, !pause> (possibly block on interrupt, but idk if that works with gpio)
            //block_for_interrupt() <- seems racy.
            goto repoll_music_op; // <- seems bad for battery, but w/e
        case(PLAYER_RESUME): //continue playing
            music_op = PLAYER_PLAY;
            mipod_in->status = STATE_PLAYING; //notify caller the resume operation has succeeded.
            break;
        case(PLAYER_STOP): //we are done playing the song, exit on out of here
            //mipod_in->status = STATE_SUCCESS; <- happens on return
            goto unload;
        case(PLAYER_RESTART): //reset the song state to the beginning and then start playing again
            music_op = PLAYER_PLAY;
            offset = 0;
            //played = 0; <- set as part of for loop
            goto restart_playing; //sets state to playing
#if 0
        case(PLAYER_FORWARD):break; //do some math, set offset/etc to +5s, skip there (maybe loading some more segments)
        case(PLAYER_REWIND):break; //do some math, set offset/etc to -5s, skip there (maybe reloading some segments)
        case(PLAYER_FORWARD_PAUSE):break; //do the math, then set state to pause
        case(PLAYER_REWIND_PAUSE):break; //do the math, then set state to pause
#endif
#ifdef __GNUC__
        default:__builtin_unreachable();
#endif
        }
    }

unload:;
    disable_interrupts();
    music_op = PLAYER_NONE;
    unload_song_header();
    return true;
}

#ifdef _MSC_VER
#pragma endregion
#endif // _MSC_VER

#ifdef _MSC_VER //TODO: verify
#pragma region startup_query
#endif // _MSC_VER

bool startup_query(void) {
    // mb_printf("Starting queried player regions and users\r\n");  
    for (int i = 0; i < TOTAL_REGIONS; i++){
        copyfromlocal((char *)q_region_lookup(mipod_in->query_data, i), REGION_NAMES[provisioned_regions[i]], UNAME_SIZE);
        // mipod_in->query_data.rids[i] = provisioned_regions[i];
    } 
    // copyfromlocal(mipod_in->query_data.rids, provisioned_regions, sizeof(provisioned_regions));
    
    for (size_t j = 0; j < TOTAL_USERS; j++) {
        copyfromlocal((char *)q_user_lookup(mipod_in->query_data, j), provisioned_users[j].name, UNAME_SIZE);
        // char *user_tmp = provisioned_users[j].name;
        // mb_printf("users_list: %s", q_user_lookup(mipod_in->query_data, i));
    }

    mb_printf("Queried player (%d regions, %d users)\r\n", TOTAL_REGIONS, TOTAL_USERS);
    // mipod_in->status = STATE_SUCCESS;
    return true;
}

bool query_song(void) {
    char *name;
    // mb_printf("Starting queried player regions and users\r\n");  
    for (int i = 0; i < NUM_REGIONS; i++){
        // char index = mipod_in->digital_data.play_data.drm.regions[i];
        // if( i > 0 && strcmp(index, 0))
        //     i = NUM_REGIONS;
        rid_to_region_name(mipod_in->digital_data.play_data.drm.regions[i], &name, false);
        strncpy((char *)q_song_region_lookup(mipod_in->query_data, i), name, UNAME_SIZE);
        // mb_printf("regions: %s", q_song_region_lookup(mipod_in->query_data, i));
    } 
    return true;
}

#ifdef _MSC_VER
#pragma endregion
#endif // _MSC_VER

#ifdef _MSC_VER //TODO: verify
#pragma region write_dout
#endif // _MSC_VER

//client can reassemble wav header
bool digitize_song(void) {
    /*
    load header
    load segment
    decrypt segment
    write decrypted segment back to shm buffer
    load next segment
    reapeat ad infinitum
    */

    //the mitre doc doesn't say anything about who can dump songs, so we will just do it for everyone.
    if (load_song_header(&mipod_in->digital_data.play_data.drm) == SONG_BADSIG) {
        return false;
    }
    uint8_t* fseg = &(mipod_in->digital_data.play_data.filedata[0]); //a pointer to the start of the segment to load within the shared memory section
    uint8_t* arm_decrypted = fseg; //a pointer to the next byte in the shared memory to write decrypted file to
    size_t decrypted_mem = 0;
    size_t segsize = current_song_header.first_segment_size;

    //load and decrypt all the segments
    size_t i = 0;
    for (; i < current_song_header.nr_segments; ++i, fseg+=segsize) {
        if (!load_song_segment(fseg, segsize, i)) {
            unload_song_header();
            memzero(mipod_in->digital_data.play_data.filedata, decrypted_mem); //more of an annoyance than actually secure, but oh well
            return false;
        }
        //decrypt and remove padding/trailers
        size_t raw = decrypt_segment_data(segment_buffer, segsize - sizeof(struct segment_trailer));
        //this math assumes that everything is properly setup within the song, so, yknow, don't be stupid... 
        segsize = ((struct segment_trailer*)((uint8_t*)segment_buffer + segsize - sizeof(struct segment_trailer)))->next_segment_size;
        copyfromlocal(arm_decrypted, segment_buffer, raw);
        decrypted_mem += raw;
        arm_decrypted += raw;
    }
    mipod_in->digital_data.wav_size = decrypted_mem;
    return true;
}

#ifdef _MSC_VER
#pragma endregion
#endif // _MSC_VER

#ifdef _MSC_VER //TODO: verify
#pragma region sharing_is_caring
#endif // _MSC_VER

/*
note: assumes that all possible users will exist on the local device (ie no cross-device song sharing, those users will be overwritten).
this seems to be in accordance with the spec, but I am not 100% sure.
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
    sign_user_block(&current_song_header, offsetof(drm_header, owner_sig));
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

#ifdef _MSC_VER //pause, resume, stop, restart, forward, rewind. TODO: verify, implement forward/rewind.
#pragma region playing_music_ops
#endif // _MSC_VER

//#define wait_for_play() do {} while(music_op!=PLAYER_PLAY) //wait for the music operation to be play (normal)
//#define wait_for_pause() do {} while(music_op!=PLAYER_PAUSE) //wait for the music operation to be pause
//#define wait_for_play_pause() do {} while(music_op>PLAYER_PAUSE) //wait for the music operation to be play or pause
//^^works because play=0 and pause=1
/*
static void pause_song(void) { //only one that doesn't rely on play_song to set state because nothing bad can happen if play_song never sees the operation
    if (music_op == PLAYER_PLAY) { //can we pause during other times?
        music_op = PLAYER_PAUSE;
        mipod_in->status = STATE_SUCCESS;
    }
    else {
        mipod_in->status = STATE_FAILED;
    }
}*/
void resume_song(void) { //success: state=>playing
    if (music_op == PLAYER_PAUSE) //only one we are allowed to resume on.
        music_op = PLAYER_RESUME;
    else
        set_status_failed();
}



 void restart_song(void) {
    if (music_op <= PLAYER_PAUSE) //works because play=0 and pause=1
        music_op = PLAYER_RESTART;
    else 
        set_status_failed();
}

 void forward_song(void) {
#if 0
    uint8_t op;
    //wait for play or pause, then make sure to save that while noting the next state should be xyz
    while ((op = music_op) > PLAYER_PAUSE) continue;
    if (op == PLAYER_PAUSE)
        music_op = PLAYER_FORWARD_PAUSE;
    else
        music_op = PLAYER_FORWARD;
    return true;
#else
    return;
#endif
}


void rewind_song(void) {
#if 0
    uint8_t op;
    while ((op = music_op) > PLAYER_PAUSE) continue;
    if (op == PLAYER_PAUSE)
        music_op = PLAYER_REWIND_PAUSE;
    else
        music_op = PLAYER_REWIND;
    return true;
#else
    return;
#endif
}

#ifdef _MSC_VER
#pragma endregion 
#endif // _MSC_VER
