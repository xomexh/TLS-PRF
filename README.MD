#  TLS PRF using modified DHSL Library code

TLS 1.2 PRF implemeneted & verified manually with PRF Test Vectors from IBM Researchers. Cross verified using prf.py

# Test Vectors
Kindly provided by IBM Researchers online.

```
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
```

# Test

The code produces expected output & has been cross verified with the above vector. 

The expected value & obtained output has been commented in the main.rs file. 

Run using ```cargo run```.