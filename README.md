secure-inline-communication-channel/
│
├── README.md
├── Makefile
├── .gitignore
│
├── network/
│   ├── setup.sh
│   ├── cleanup.sh
│   └── configure_firewall.sh
│
├── src/
│   ├── common/
│   │   ├── crypto.c
│   │   ├── crypto.h
│   │   ├── packet.c
│   │   ├── packet.h
│   │   ├── checksum.c
│   │   └── checksum.h
│   │
│   ├── device1/
│   │   ├── encryptor.c
│   │   └── handshake.c
│   │
│   ├── device2/
│   │   ├── decryptor.c
│   │   └── handshake.c
│   │
│   ├── sender/
│   │   └── client.c
│   │
│   └── receiver/
│       └── server.c
│
├── tests/
│   ├── test_crypto.c
│   ├── test_packet.c
│   └── test_transfer.sh
│
└── docs/
    ├── architecture.md
    └── screenshots/
