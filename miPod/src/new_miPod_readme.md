Changed the client API based on old miPod.c and cacti_sig from mb/src.

Something not sure here...
- cacti_sig.c will replace the main.c
- cacti_sig.h will replace the miPod.h
- new constants.h copy from mb/src with modification



## Important Data Structure

- old **cmd_channel** structure changed to **mipod_buffer**

based on mb/src/cacti_sig.c line 176

`static struct mipod_buffer* const mipod_in = (void*)SHARED_DDR_BASE;  //this ends up as a constant address`

and old-drm-main.c line 41

`volatile cmd_channel *c = (cmd_channel*)SHARED_DDR_BASE;`

- old internal_state change to mipod_buffer->status

- For miPod state, need STATE_STOPPED one

- song header changed to drm

> a pointer to the start of the segment to load within the shared memory section song data: filedata[0]



## Some Modification to Secure Copy

- miPod-login

```c
strcpy --> strncpy

strncpy((void*)c->login_data.name, username, sizeof(UNAME_SIZE));
strncpy((void*)c->login_data.pin, pin, sizeof(PIN_SIZE));
```

- miPod-share_song

```c
strncpy((char *)c->login_data.name, username, sizeof(UNAME_SIZE));
```



## Not sure things

- miPod state needs STATE_STOPPED

- New query function in cacti_sig.h (will replace the miPod.h)

```c
// simulate array of 64B names without pointer indirection
#define q_region_lookup(q, i) (q.rids[i])
#define q_user_lookup(q, i) (q.users_list[UNAME_SIZE][i])

// query information for song (drm)
#define q_song_region_lookup(q, i) (q.regions[i])
#define q_song_user_lookup(q, i) (q.shared_users[UNAME_SIZE][i])
```

- changed API from mb/src/cacti_sig.c

`query_player() == startup_query()`

- no query_song API, tried to use play_data structure, need to be fixed



> Some secure definition not used in Client Interface, like some owner_sig in drm_header, need to be updated.
