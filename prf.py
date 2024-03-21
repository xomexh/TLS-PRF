import hmac
import hashlib

def calculate_hmac_sha256(key, message):
    hmac_sha256 = hmac.new(key.encode('utf-8'), message.encode('utf-8'), hashlib.sha256)
    return hmac_sha256.hexdigest()

seed =   "a0ba9f936cda311827a6f796ffd5198c"
secret = "9bbe436ba940f017b17652849a71db35"
label =  "74657374206c6162656c"

a=["","","","",""]
phash= ["","","","",""]
a[0] = label + seed
a[1] = calculate_hmac_sha256(secret, a[0])

# for i in range(4):
#     a[i+1]=calculate_hmac_sha256(secret, a[i])
#     phash[i]=phash[i-1]+calculate_hmac_sha256(secret, (a[i+1]+a[0]))

print(a);
print(phash);

