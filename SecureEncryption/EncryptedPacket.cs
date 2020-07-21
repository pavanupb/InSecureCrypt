﻿using System;
using System.Collections.Generic;
using System.Text;

namespace SecureEncryption
{
    public class EncryptedPacket
    {
        public byte[] EncryptedSessionKey;
        public byte[] EncryptedData;
        public byte[] Iv;
        public byte[] Hmac;
    }
}
