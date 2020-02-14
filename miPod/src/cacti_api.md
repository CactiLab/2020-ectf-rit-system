    
The C structs/etc mentioned herein can be obtained from the cacti_sig.c file in the mb directory.  
Each operation is transmitted to the firmware as follows:  
  * mipod_buffer.operation is set to the requested operations (see enum MIPOD_OPS)  
  * any ancilliary information required is copied into the appropriate member of the mipod_buffer union.  
  * a GPIO is triggered by the mipod client to tell the firmware to process the song. (I would recommend using mmap over system("devmem"), but ymmv)    
  * the mipod client should wait for the shared memory mipod_buffer.status member to change states (in a spinloop most likely), then take action based on the result of that status (success/fail/playing/etc). the firmware will NOT use this member outside of reporting results, so the mipod client must manage it themselves.  

The operations requiring extra data are as follows:  
  * login => the username and pin. (struct mipod_login_data). all data should be nul-padded to the appropriate size.  
  * play => the song file. (struct mipod_play_data). The drm header should be at the head of the file, with all data statically allocated (so no resizing is required).  
  * query => an output buffer to be filled by the firmware. (struct mipod_query_data).   
  * digitize => the song to be digitized. (struct mipod_digital_data). this WILL be overwritten in-place by the firmware with the raw wav song.  
  * share => the user to share with and the drm header of the file to be shared (NOT the full file). The header will be updated to reflect the new state. (struct mipod_share_data).  

There are 7 "play" operations, 2 of which (forward/rewind) are optional (but should be pretty easy due to the design of .WAV files), 5 functional operations, and one operation with client-side implementation (querying song data).  
A brief summary of the operations the client must perform are as follows (assuming a successful status code comes back).  
Unless otherwise noted, all operations require that a song not be playing at the time of the attempt:  
  * play => nothing  
  * pause => (requires a playing song) nothing  
  * resume => (requires a playing song) nothing  
  * restart => (requires a playing song) nothing  
  * stop => (requires a playing song) nothing (note that this unloads the current song)  
  * forward => (requires a playing song) nothing  
  * rewind => (requires a playing song) nothing  
  * login => nothing   
  * logout => nothing  
  * startup query => the firmware will provide an array of region ID's and a list of usernames. do an RID lookup and print everything.  
  * query song data => dump the drm header metadata yourself and print it. the firmware is not needed for this.  
  * digitizing => write the .wav chunk to whatever location is needed.  
  * share song => use the returned drm header and overwrite the drm header on the existing file.  
