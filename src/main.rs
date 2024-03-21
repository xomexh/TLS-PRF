/*

P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
                       HMAC_hash(secret, A(2) + seed) +
                       HMAC_hash(secret, A(3) + seed) + ...
A() is defined as:

A(0) = seed
A(i) = HMAC_hash(secret, A(i-1))

TLS's PRF is created by applying P_hash to the secret as:

PRF(secret, label, seed) = P_<hash>(secret, label + seed)

# Generating 100 bytes of pseudo-randomness using TLS1.2PRF-SHA256
Secret (16 bytes):
0000    9b be 43 6b a9 40 f0 17    ..Ck....
0008    b1 76 52 84 9a 71 db 35    .vR..q.5

Seed (16 bytes):
0000    a0 ba 9f 93 6c da 31 18    ....l.1.
0008    27 a6 f7 96 ff d5 19 8c    ........

Label (10 bytes):
0000    74 65 73 74 20 6c 61 62    test lab
0008    65 6c                      el

Output (100 bytes):
0000    e3 f2 29 ba 72 7b e1 7b    ....r...
0008    8d 12 26 20 55 7c d4 53    ... U..S
0010    c2 aa b2 1d 07 c3 d4 95    ........
0018    32 9b 52 d4 e6 1e db 5a    2.R....Z
0020    6b 30 17 91 e9 0d 35 c9    k0....5.
0028    c9 a4 6b 4e 14 ba f9 af    ..kN....
0030    0f a0 22 f7 07 7d ef 17    ........
0038    ab fd 37 97 c0 56 4b ab    ..7..VK.
0040    4f bc 91 66 6e 9d ef 9b    O..fn...
0048    97 fc e3 4f 79 67 89 ba    ...Oyg..
0050    a4 80 82 d1 22 ee 42 c5    ......B.
0058    a7 2e 5a 51 10 ff f7 01    ..ZQ....
0060    87 34 7b 66                .4.f



A0:
0000 74 65 73 74 20 6c 61 62
0008 65 6c a0 ba 9f 93 6c da
0010 31 18 27 a6 f7 96 ff d5
0018 19 8c
A1:
0000 9f 5b b1 29 e2 f8 0a a4
0008 7b 67 05 b3 3e 21 4c c5
0010 e5 09 f2 83 e8 7b 3b e5
0018 e1 da a7 44 92 27 7d a1
P1:
0000 e3 f2 29 ba 72 7b e1 7b
0008 8d 12 26 20 55 7c d4 53
0010 c2 aa b2 1d 07 c3 d4 95
0018 32 9b 52 d4 e6 1e db 5a
A2:
0000 fc 16 6a 08 80 91 f7 6f
0008 af 99 35 9a 69 93 8f 75
0010 c1 54 24 63 8f 61 38 46
0018 34 24 37 32 b6 28 72 7b
P2:
0000 6b 30 17 91 e9 0d 35 c9
0008 c9 a4 6b 4e 14 ba f9 af
0010 0f a0 22 f7 07 7d ef 17
0018 ab fd 37 97 c0 56 4b ab
A3:
0000 fe 5f 7d 49 75 e1 23 c0
0008 d4 33 a3 a2 61 b6 42 c0
0010 58 04 46 46 1a f0 88 f0
0018 c7 9f 43 45 72 a1 a1 a6
P3:
0000 4f bc 91 66 6e 9d ef 9b
0008 97 fc e3 4f 79 67 89 ba
0010 a4 80 82 d1 22 ee 42 c5
0018 a7 2e 5a 51 10 ff f7 01
A4:
0000 3e fb 20 52 e4 76 f9 6c
0008 64 8d ca 6d 2d 00 8f b9
0010 75 ef b6 a4 83 60 be ec
0018 fd 47 a8 51 2b e7 3e eb
P4:
0000 87 34 7b 66 71 5a 92 bf
0008 c6 21 f0 17 10 81 1a b3
0010 8f 71 0e 7b 33 2f 44 10
0018 9e 42 fd 63 e4 7f 62 c0
result:
0000 e3 f2 29 ba 72 7b e1 7b
0008 8d 12 26 20 55 7c d4 53
0010 c2 aa b2 1d 07 c3 d4 95
0018 32 9b 52 d4 e6 1e db 5a
0020 6b 30 17 91 e9 0d 35 c9
0028 c9 a4 6b 4e 14 ba f9 af
0030 0f a0 22 f7 07 7d ef 17
0038 ab fd 37 97 c0 56 4b ab
0040 4f bc 91 66 6e 9d ef 9b
0048 97 fc e3 4f 79 67 89 ba
0050 a4 80 82 d1 22 ee 42 c5
0058 a7 2e 5a 51 10 ff f7 01
0060 87 34 7b 66

P_hash(secret, seed) = HMAC_hash(secret, A(i)+seed )
A(0)=seed;
A(i) = HMAC_hash(secret, A(i-1));
A(1) = HMAC_hash(secret, A(0));

PRF(secret, label, seed) = P_<hash>(secret, (label + seed))
                         = HMAC_hash(secret, A(i)+( label+seed ))
                         = HMAC_hash( secret, A(i)+A(0) )

need 100 bytes, so 4 iterations & truncate rest bytes.

    // let seed = "some seed";
    // let secret = "some secret";

    // let a0 = label+seed;
    // let mut p_hash;

    // let a1 = rapid_hmac(secret, a0);
    // p_hash = p_hash + rapid_hamc(secret, format!("{a1}{a0}"));

    // let a2 = rapid_hmac(secret, a1);
    // p_hash = p_hash + rapid_hamc(secret, format!("{a2}{a0}"));

    // let a3 = rapid_hmac(secret, a2);
    // p_hash = p_hash + rapid_hamc(secret, format!("{a3}{a0}"));

    // let a4 = rapid_hmac(secret, a3);
    // p_hash = p_hash + rapid_hamc(secret, format!("{a4}{a0}"));

    // let prf = p_hash
*/


#![allow(unused_imports)]
#![allow(non_snake_case)]
#![allow(unused_variables)]

use rapid_hmac::hmac_sha256;
use std::thread;
use std::time::Duration;

#[tokio::main]
async fn main() {

    let seed =   "a0ba9f936cda311827a6f796ffd5198c";
    let secret = "0x9bbe436ba940f017b17652849a71db35";
    let label =  "74657374206c6162656c";

    let a = format!("{label}{seed}");

    let a1 = hmac_sha256(secret.to_string(), format!("0x{label}{seed}")).await;
    dbg!(&a1);
    //9f5bb129e2f80aa47b6705b33e214cc5e509f283e87b3be5e1daa74492277da1

    thread::sleep(Duration::from_secs(5));
    let p1 = hmac_sha256(secret.to_string(), format!("0x{a1}{a}")).await;
    //e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a

    thread::sleep(Duration::from_secs(5));
    let a2 = hmac_sha256(secret.to_string(), format!("0x{a1}")).await;
    //fc166a088091f76faf99359a69938f75c15424638f61384634243732b628727b

    thread::sleep(Duration::from_secs(5));
    let p2 = hmac_sha256(secret.to_string(), format!("0x{a2}{a}")).await;
    //6b301791e90d35c9c9a46b4e14baf9af0fa022f7077def17abfd3797c0564bab

    thread::sleep(Duration::from_secs(5));
    let a3 = hmac_sha256(secret.to_string(), format!("0x{a2}")).await;
    //fe5f7d4975e123c0d433a3a261b642c0580446461af088f0c79f434572a1a1a6

    thread::sleep(Duration::from_secs(5));
    let p3 = hmac_sha256(secret.to_string(), format!("0x{a3}{a}")).await;
    //4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff701
    thread::sleep(Duration::from_secs(5));
    let a4 = hmac_sha256(secret.to_string(), format!("0x{a3}")).await;
    //3efb2052e476f96c648dca6d2d008fb975efb6a48360beecfd47a8512be73eeb

    thread::sleep(Duration::from_secs(5));
    let p4 = hmac_sha256(secret.to_string(), format!("0x{a4}{a}")).await;
    //87347b66715a92bfc621f01710811ab38f710e7b332f44109e42fd63e47f62c0

    let prf = p1 + &p2 + &p3 + &p4;
    dbg!(&prf[..200]);
    //e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a6b301791e90d35c9c9a46b4e14baf9af0fa022f7077def17abfd3797c0564bab4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff70187347b66

    //e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a6b301791e90d35c9c9a46b4e14baf9af0fa022f7077def17abfd3797c0564bab4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff70187347b66715a92bfc621f01710811ab38f710e7b332f44109e42fd63e47f62c0

    //now truncate prf at 100 bytes ( 200 bit length)


    //let mut p_hash =  String::new();
    //let mut a_prev = a.clone();

    // for _ in 0..4 {
    //     let a_i = hmac_sha256(a_prev.to_string(), secret.to_owned()).await;
    //     let p_i = hmac_sha256(secret.to_string(), format!("{}{}", a_i, a)).await;
    //     p_hash.push_str(&p_i);
    //     a_prev = a_i;
    // }

    // Test Lib
    //  let key = String::from("0x9bbe436ba940f017b17652849a71db35");
    //  let message = String::from("0x74657374206c6162656ca0ba9f936cda311827a6f796ffd5198c");
    //  let sign_test = hmac_sha256(key, message).await;
    
}
