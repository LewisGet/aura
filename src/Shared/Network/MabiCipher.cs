using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Aura.Shared.Util;

namespace Aura.Shared.Network
{
	/// <summary>
	/// Implements a Mabinogi-style AES cipher
	/// </summary>
	public sealed class MabiCipher
	{
		/// <summary>
		/// Any data left over after processing all multiples of 16
		/// is XORed with this array.
		/// </summary>
		private static readonly byte[] _remainderMask = { 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0xf, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78 };

		/// <summary>
		/// The key used to init the ciphers
		/// </summary>
		private static readonly byte[] _key =
		{
				0x8F, 0xCA, 0x2D, 0x32,
				0x7C, 0x50, 0xEA, 0xE1,
				0xB1, 0x09, 0xD0, 0x94,
				0x7E, 0x64, 0xAD, 0x3C
		};

		/// <summary>
		/// Cipher used for encrypting packets sent to the client
		/// </summary>
		private readonly AesFastEngine _encryptCipher;

		/// <summary>
		/// Cipher used for encrypting packets recv'd from the client
		/// </summary>
		private readonly AesFastEngine _decryptCipher;

		/// <summary>
		/// Creates a new instance of the mabi cipher
		/// </summary>
		public MabiCipher()
		{
			_encryptCipher = new AesFastEngine();
			_decryptCipher = new AesFastEngine();

			_encryptCipher.Init(true, _key);
			_decryptCipher.Init(false, _key);
		}

		/// <summary>
		/// Decrypts a packet recv'd from the client
		/// </summary>
		/// <param name="packet"></param>
		public void DecryptPacket(byte[] packet)
		{
			DecryptPacket(packet, 0, packet.Length);
		}

		/// <summary>
		/// Decrypts a packet recv'd from the client
		/// </summary>
		/// <param name="packet"></param>
		/// <param name="offset"></param>
		/// <param name="count"></param>
		public void DecryptPacket(byte[] packet, int offset, int count)
		{
			CryptPacket(_decryptCipher, packet, offset, count);
		}

		/// <summary>
		/// Encrypts a packet for sending to the client
		/// </summary>
		/// <param name="packet"></param>
		public void EncryptPacket(byte[] packet)
		{
			EncryptPacket(packet, 0, packet.Length);
		}

		/// <summary>
		/// Encrypts a packet for sending to the client
		/// </summary>
		/// <param name="packet"></param>
		/// <param name="offset"></param>
		/// <param name="count"></param>
		public void EncryptPacket(byte[] packet, int offset, int count)
		{
			CryptPacket(_encryptCipher, packet, offset, count);
		}

		/// <summary>
		/// Actually does the crypt operation
		/// </summary>
		/// <param name="cipher"></param>
		/// <param name="packet"></param>
		/// <param name="offset"></param>
		/// <param name="count"></param>
		private static void CryptPacket(AesFastEngine cipher, byte[] packet, int offset, int count)
		{
			if (packet[5] == 0x3) // Flag 3 means no encryption
			{
				return;
			}

			int ptr = offset, ctr = count;

			var temp = new byte[16];

			// Read and encrypt 16 byte chunks with the provided cipher
			// Write the processed values right back to the packet
			while (ctr >= 16)
			{
				// Mabi's cipher treats blocks as Big Endian
				// But standard AES treats them as Little, so we need to swap our data
				for (var i = 0; i < 16; i += 4)
				{
					temp[i] = packet[ptr + i + 3];
					temp[i + 1] = packet[ptr + i + 2];
					temp[i + 2] = packet[ptr + i + 1];
					temp[i + 3] = packet[ptr + i];
				}

				cipher.ProcessBlock(temp, 0, temp, 0);

				for (var i = 0; i < 16; i += 4)
				{
					packet[ptr + i] = temp[i + 3];
					packet[ptr + i + 1] = temp[i + 2];
					packet[ptr + i + 2] = temp[i + 1];
					packet[ptr + i + 3] = temp[i];
				}

				ptr += 16;
				ctr -= 16;
			}

			if (ctr != 0) // If we have leftovers, we'd better eat - err, mask - them
			{
				for (var i = 0; i < ctr; ++i)
				{
					packet[ptr] ^= _remainderMask[i];
					ptr++;
				}
			}
		}
	}
}
