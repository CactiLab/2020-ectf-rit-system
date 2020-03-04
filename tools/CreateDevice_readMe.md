Before running the script install two python packages argon2 and pbkdf2, then run the createDevice script same as the mitre reference: 

```
sudo apt install python3-pip
python3 -m pip install argon2-cffi
pip3 install pbkdf2

./createDevice --region-list "United States" "Japan" --region-secrets-path global_provisioning/region.secrets --user-list "drew" "ben" "misha" --user-secrets-path global_provisioning/user.secrets --device-dir device1
```

