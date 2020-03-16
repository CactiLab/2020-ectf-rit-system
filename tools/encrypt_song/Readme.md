usage:

encrypt the song:
./protectRITSong.py --region-list "United States" "Japan" "Australia" --region-secrets-path region.secrets --outfile protectRITdemo.drm --infile Sound-Bite_One-Small-Step.wav --owner "misha" --user-secrets-path user.secrets

decrypt the song:
./unprotectedSong.py --infile protectRITdemo.drm --outfile unprotectRIT.wav --keyfile aes.key