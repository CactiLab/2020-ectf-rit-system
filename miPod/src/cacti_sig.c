/*
 * eCTF Collegiate 2020 miPod Example Code -- RIT design
 * Linux-side DRM driver
 */


#include "miPod.h"

#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <linux/gpio.h>
#include <string.h>
#include <stddef.h>


volatile cmd_channel *c;


//////////////////////// UTILITY FUNCTIONS ////////////////////////


// sends a command to the microblaze using the shared command channel and interrupt
void send_command(int operation) {
    memcpy((void*)&c->operation, &operation, 1);

    //trigger gpio interrupt
    system("devmem 0x41200000 32 0");
    system("devmem 0x41200000 32 1");
}


// parses the input of a command with up to two arguments
// any arguments not present will be set to NULL
void parse_input(char *input, char **cmd, char **arg1, char **arg2) {
    *cmd = strtok(input, " \r\n");
    *arg1 = strtok(NULL, " \r\n");
    *arg2 = strtok(NULL, " \r\n");
}


// prints the help message while not in playback
void print_help() {
    mp_printf("miPod options:\r\n");
    mp_printf("  login <username> <pin>: log on to a miPod account (must be logged out)\r\n");
    mp_printf("  logout: log off of a miPod account (must be logged in)\r\n");
    mp_printf("  query <song.drm>: display information about the song\r\n");
    mp_printf("  share <song.drm> <username>: share the song with the specified user\r\n");
    mp_printf("  play <song.drm>: play the song\r\n");
    mp_printf("  digital_out <song.drm>: play the song to digital out\r\n");
    mp_printf("  exit: exit miPod\r\n");
    mp_printf("  help: display this message\r\n");
}


// prints the help message while in playback
void print_playback_help() {
    mp_printf("miPod playback options:\r\n");
    mp_printf("  stop: stop playing the song\r\n");
    mp_printf("  pause: pause the song\r\n");
    mp_printf("  resume: resume the paused song\r\n");
    mp_printf("  restart: restart the song\r\n");
    mp_printf("  ff: fast forwards 5 seconds(unsupported)\r\n");
    mp_printf("  rw: rewind 5 seconds (unsupported)\r\n");
    mp_printf("  help: display this message\r\n");
}


// loads a file into the song buffer with the associate
// returns the size of the file or 0 on error
size_t load_file(char *fname, struct mipod_digital_data *digital_song) {
    struct mipod_play_data * song_buf;
    // char *song_buf;
    int fd;
    struct stat sb;

    fd = open(fname, O_RDONLY);
    if (fd == -1){
        mp_printf("Failed to open file! Error = %d\r\n", errno);
        return 0;
    }

    if (fstat(fd, &sb) == -1){
        mp_printf("Failed to stat file! Error = %d\r\n", errno);
        return 0;
    }

    read(fd, song_buf, sb.st_size);
    digital_song->wav_size = song_buf->drm.wavdata.subchunk2_size;
    digital_song->drm = song_buf->drm;
    memcpy(digital_song->filedata, song_buf->filedata, sb.st_size - sizeof(song_buf->drm));
    
    close(fd);

    mp_printf("Loaded file into shared buffer (%dB)\r\n", sb.st_size);
    return sb.st_size;
}


//////////////////////// COMMAND FUNCTIONS ////////////////////////


// attempts to log in for a user
void login(char *username, char *pin) {
    if (!username || !pin) {
        mp_printf("Invalid user name/PIN\r\n");
        print_help();
        return;
    }

    // drive DRM
    strncpy((void*)c->login_data.name, username, sizeof(UNAME_SIZE));
    strncpy((void*)c->login_data.pin, pin, sizeof(PIN_SIZE));
    send_command(MIPOD_LOGIN);
}


// logs out for a user
void logout() {
    // drive DRM
    send_command(MIPOD_LOGOUT);
}


// queries the DRM about the player
// DRM will fill shared buffer with query content
void query_player() {
    // drive DRM
    send_command(MIPOD_QUERY);
    while (c->status == STATE_FAILED) continue; // wait for DRM to start STATE_WORKING
    while (c->status == STATE_WORKING) continue; // wait for DRM to dump file

    // print query results
    mp_printf("Regions: %s", q_region_lookup(c->query_data, 0));
    for (int i = 1; i < sizeof(c->query_data.rids); i++) {
        printf(", %s", q_region_lookup(c->query_data, i));
    }
    printf("\r\n");

    mp_printf("Authorized users: ");
    if (c->query_data.users_list) {
        printf("%s", q_user_lookup(c->query_data, 0));
        for (int i = 1; i < sizeof(c->query_data.users_list); i++) {
            printf(", %s", q_user_lookup(c->query_data, i));
        }
    }
    printf("\r\n");
}


// queries the DRM about a song
void query_song(char *song_name) {
    // load the song into the shared buffer
    if (!load_file(song_name, &c->digital_data)) {
        mp_printf("Failed to load song!\r\n");
        return;
    }

    // drive DRM
    // send_command(MIPOD_QUERY);
    while (c->status == STATE_FAILED) continue; // wait for DRM to start STATE_WORKING
    while (c->status == STATE_WORKING) continue; // wait for DRM to finish

    // print query results

    mp_printf("Regions: %s", q_song_region_lookup(c->digital_data.drm, 0));
    for (int i = 1; i < sizeof(c->digital_data.drm.regions); i++) {
        printf(", %s", q_song_region_lookup(c->digital_data.drm, i));
    }
    printf("\r\n");

    mp_printf("Owner: %s", c->digital_data.drm.owner);
    printf("\r\n");

    mp_printf("Authorized users: ");
    if (c->query_data.users_list) {
        printf("%s", q_song_user_lookup(c->digital_data.drm, 0));
        for (int i = 1; i < sizeof(c->digital_data.drm.shared_users); i++) {    
            if (q_song_user_lookup(c->digital_data.drm, i) != 0)
            {
                printf(", %s", q_song_user_lookup(c->digital_data.drm, i));
            }           
        }
    }
    printf("\r\n");
}


// attempts to share a song with a user
void share_song(char *song_name, char *username) {
    int fd;
    unsigned int length;
    ssize_t wrote, written = 0;

    if (!username) {
        mp_printf("Need song name and username\r\n");
        print_help();
    }

    // load the song into the shared buffer
    if (!load_file(song_name, (void*)&c->digital_data)) {
        mp_printf("Failed to load song!\r\n");
        return;
    }

    strncpy((char *)c->share_data.target_name, username, sizeof(UNAME_SIZE));
    c->share_data.drm = c->play_data.drm;

    // drive DRM
    send_command(MIPOD_SHARE);
    while (c->status == STATE_FAILED) continue; // wait for DRM to start STATE_WORKING
    while (c->status == STATE_WORKING) continue; // wait for DRM to share song

    // request was rejected if WAV length is 0
    length = c->digital_data.wav_size;
    if (length == 0) {
        mp_printf("Share rejected\r\n");
        return;
    }

    length = length + 1368;

    // open output file
    fd = open(song_name, O_WRONLY);
    if (fd == -1){
        mp_printf("Failed to open file! Error = %d\r\n", errno);
        return;
    }

    // write song dump to file
    mp_printf("Writing song to file '%s' (%dB)\r\n", song_name, length);
    while (written < length) {
        wrote = write(fd, (char *)&c->share_data.drm + written, length - written);
        if (wrote == -1) {
            mp_printf("Error in writing file! Error = %d\r\n", errno);
            return;
        }
        written += wrote;
    }
    close(fd);
    mp_printf("Finished writing file\r\n");
}


// plays a song and enters the playback command loop
int play_song(char *song_name) {
    char usr_cmd[USR_CMD_SZ + 1], *cmd = NULL, *arg1 = NULL, *arg2 = NULL;

    // load song into shared buffer
    if (!load_file(song_name, (void*)&c->digital_data)) {
        mp_printf("Failed to load song!\r\n");
        return 0;
    }

    // drive the DRM
    send_command(MIPOD_PLAY);
    while (c->status == STATE_FAILED) continue; // wait for DRM to start playing

    // play loop
    while(1) {
        // get a valid command
        do {
            print_prompt_msg(song_name);
            fgets(usr_cmd, USR_CMD_SZ, stdin);

            // exit playback loop if DRM has finished song
            if (c->status == STATE_FAILED) {
                mp_printf("Song finished\r\n");
                return 0;
            }
        } while (strlen(usr_cmd) < 2);

        // parse and handle command
        parse_input(usr_cmd, &cmd, &arg1, &arg2);
        if (!cmd) {
            continue;
        } else if (!strcmp(cmd, "help")) {
            print_playback_help();
        } else if (!strcmp(cmd, "resume")) {
            send_command(MIPOD_PLAY);
            usleep(200000); // wait for DRM to print
        } else if (!strcmp(cmd, "pause")) {
            send_command(MIPOD_PAUSE);
            usleep(200000); // wait for DRM to print
        } else if (!strcmp(cmd, "stop")) {
            send_command(MIPOD_STOP);
            usleep(200000); // wait for DRM to print
            break;
        } else if (!strcmp(cmd, "restart")) {
            send_command(MIPOD_RESTART);
        } else if (!strcmp(cmd, "exit")) {
            mp_printf("Exiting...\r\n");
            send_command(MIPOD_STOP);
            return -1;
        } else if (!strcmp(cmd, "rw")) {
            mp_printf("Unsupported feature.\r\n\r\n");
            print_playback_help();
        } else if (!strcmp(cmd, "ff")) {
            mp_printf("Unsupported feature.\r\n\r\n");
            print_playback_help();
        } else if (!strcmp(cmd, "lyrics")) {
            mp_printf("Unsupported feature.\r\n\r\n");
            print_playback_help();
        } else {
            mp_printf("Unrecognized command.\r\n\r\n");
            print_playback_help();
        }
    }

    return 0;
}


// turns DRM song into original WAV for digital output
void digital_out(char *song_name) {
    char fname[64];

    // load file into shared buffer
    if (!load_file(song_name, (void*)&c->digital_data)) {
        mp_printf("Failed to load song!\r\n");
        return;
    }

    // drive DRM
    send_command(MIPOD_DIGITAL);
    while (c->status == STATE_FAILED) continue; // wait for DRM to start STATE_WORKING
    while (c->status == STATE_WORKING) continue; // wait for DRM to dump file

    // open digital output file
    int written = 0, wrote, length = c->digital_data.wav_size + 8;   // this 8???
    sprintf(fname, "%s.dout", song_name);
    int fd = open(fname, O_WRONLY | O_CREAT | O_TRUNC);
    if (fd == -1){
        mp_printf("Failed to open file! Error = %d\r\n", errno);
        return;
    }

    // write song dump to file
    mp_printf("Writing song to file '%s' (%dB)\r\n", fname, length);
    while (written < length) {
        wrote = write(fd, (char *)&c->digital_data + written, length - written);
        if (wrote == -1) {
            mp_printf("Error in writing file! Error = %d \r\n", errno);
            return;
        }
        written += wrote;
    }
    close(fd);
    mp_printf("Finished writing file\r\n");
}


//////////////////////// MAIN ////////////////////////


int main(int argc, char** argv)
{
    int mem;
    char usr_cmd[USR_CMD_SZ + 1], *cmd = NULL, *arg1 = NULL, *arg2 = NULL;
    memset(usr_cmd, 0, USR_CMD_SZ + 1);

    // open command channel
    mem = open("/dev/uio0", O_RDWR);
    c = mmap(NULL, sizeof(cmd_channel), PROT_READ | PROT_WRITE,
             MAP_SHARED, mem, 0);
    if (c == MAP_FAILED){
        mp_printf("MMAP Failed! Error = %d\r\n", errno);
        return -1;
    }
    mp_printf("Command channel open at %p (%dB)\r\n", c, sizeof(cmd_channel));

    // dump player information before command loop
    query_player();

    // go into command loop until exit is requested
    while (1) {
        // get command
        print_prompt();
        fgets(usr_cmd, USR_CMD_SZ, stdin);

        // parse and handle command
        parse_input(usr_cmd, &cmd, &arg1, &arg2);
        if (!cmd) {
            continue;
        } else if (!strcmp(cmd, "help")) {
            print_help();
        } else if (!strcmp(cmd, "login")) {
            login(arg1, arg2);
        } else if (!strcmp(cmd, "logout")) {
            logout();
        } else if (!strcmp(cmd, "query")) {
        	query_song(arg1);
        } else if (!strcmp(cmd, "play")) {
            // break if exit was commanded in play loop
            if (play_song(arg1) < 0) {
                break;
            }
        } else if (!strcmp(cmd, "digital")) {
        	digital_out(arg1);
        } else if (!strcmp(cmd, "share")) {
            share_song(arg1, arg2);
        } else if (!strcmp(cmd, "exit")) {
            mp_printf("Exiting...\r\n");
            break;
        } else {
            mp_printf("Unrecognized command.\r\n\r\n");
            print_help();
        }
    }

    // unmap the command channel
    munmap((void*)c, sizeof(cmd_channel));

    return 0;
}
