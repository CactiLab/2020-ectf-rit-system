/*
 * miPod.h
 *
 *  Created on: Jan 9, 2020
 *      Author: ectf
 */

#ifndef SRC_MIPOD_H_
#define SRC_MIPOD_H_

#include <stdint.h>
#include "constants.h"


#define TOTAL_USERS 64


// miPod constants
#define USR_CMD_SZ 64

// protocol constants. Defined at constants.h
//#define MAX_REGIONS 64
//#define REGION_NAME_SZ 64
//#define MAX_USERS 64
//#define USERNAME_SZ 64
//#define MAX_PIN_SZ 64
//#define MAX_SONG_SZ (1<<25)

// printing utility
#define MP_PROMPT "mP> "
#define mp_printf(...) printf(MP_PROMPT __VA_ARGS__)

#define USER_PROMPT "miPod %s# "
#define print_prompt() printf(USER_PROMPT, "")
#define print_prompt_msg(...) printf(USER_PROMPT, __VA_ARGS__)

// struct to interpret shared buffer as a query
/*
typedef struct {
    int num_regions;
    int num_users;
    char owner[USERNAME_SZ];
    char regions[MAX_REGIONS * REGION_NAME_SZ];
    char users[MAX_USERS * USERNAME_SZ];
} query;
*/

// simulate array of 64B names without pointer indirection
#define q_region_lookup(q, i) (q.regions + (i * REGION_NAME_SZ))
#define q_user_lookup(q, i) (q.users_list + (i * UNAME_SIZE))

// query information for song (drm)
#define q_song_region_lookup(q,i) (q.song_regions + (i * REGION_NAME_SZ))
#define q_song_user_lookup(q, i) (q.shared_users + (i * UNAME_SIZE))


// struct to interpret drm metadata
/*
typedef struct __attribute__((__packed__)) {
    char md_size;
    char owner_id;
    char num_regions;
    char num_users;
    char buf[];
} drm_md;
*/

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

// This is for drm metadata
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

struct segment_trailer {
    uint8_t id[SONGID_LEN];
    uint32_t idx;
    uint32_t next_segment_size;
    uint8_t sig[HMAC_SIG_SIZE];
    char _pad_[40]; //do not use this. for cryptographic padding purposes only.
};

struct {
    char a[0-!(sizeof(struct segment_trailer) == 128 && CIPHER_BLOCKSIZE == 64)]; //if the segment trailer requirements fail, this will break.
};

// struct to interpret shared buffer as a drm song file
// packing values skip over non-relevant WAV metadata

// need to be modified
/*
typedef struct __attribute__((__packed__)) {
    char packing1[4];
    int file_size;
    char packing2[32];
    int wav_size;
    drm_md md;
} song;
*/


// accessors for variable-length metadata fields

// need to be modified
//#define get_drm_rids(d) (d.md.buf)
//#define get_drm_uids(d) (d.md.buf + d.md.num_regions)
//#define get_drm_song(d) ((char *)(&d.md) + d.md.md_size)


// shared buffer values
/*
enum commands { QUERY_PLAYER, QUERY_SONG, LOGIN, LOGOUT, SHARE, PLAY, STOP, DIGITAL_OUT, PAUSE, RESTART, FF, RW };
enum states   { STOPPED, WORKING, PLAYING, PAUSED };
*/
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
    STATE_PLAYING, //indicates that the firmware has started playing audio
	STATE_STOPPED
};

// struct to interpret shared command channel

/*
typedef volatile struct __attribute__((__packed__)) {
    char cmd;                   // from commands enum
    char drm_state;             // from states enum
    char login_status;          // 0 = logged off, 1 = logged on
    char padding;               // not used
    char username[USERNAME_SZ]; // stores logged in or attempted username
    char pin[MAX_PIN_SZ];       // stores logged in or attempted pin

    // shared buffer is either a drm song or a query
    union {
        song song;
        query query;
        char buf[MAX_SONG_SZ]; // sets correct size of cmd_channel for allocation
    };
} cmd_channel;
*/

/*
checks to see if the shared user entry at <idx_> is in use.
*/
#define CURRENT_DRM_SHARED_EMPTY_SLOT(idx_) (current_song_header.shared_users[idx_][0] == '0')

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

#endif /* SRC_MIPOD_H_ */
