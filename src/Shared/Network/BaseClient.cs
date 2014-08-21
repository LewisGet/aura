﻿// Copyright (c) Aura development team - Licensed under GNU GPL
// For more information, see license file in the main folder

using System;
using System.Net.Sockets;
using Aura.Shared.Util;

namespace Aura.Shared.Network
{
	/// <summary>
	/// Base client, for specialized client classes in the servers.
	/// </summary>
	public abstract class BaseClient
	{
		// Largest known packet is composing on R1, up to ~3700 bytes.
		private const int BufferDefaultSize = 4096;

		public Socket Socket { get; set; }
		public byte[] Buffer { get; set; }
		public ClientState State { get; set; }
		public MabiCipher Cipher { get; protected set; }

		private string _address;
		public string Address
		{
			get
			{
				if (_address == null)
				{
					try
					{
						_address = this.Socket.RemoteEndPoint.ToString();
					}
					catch
					{
						_address = "?";
					}
				}

				return _address;
			}
		}

		protected BaseClient()
		{
			this.Buffer = new byte[BufferDefaultSize];
			this.Cipher = new MabiCipher();
		}

		public bool Is(ClientState state)
		{
			return (this.State == state);
		}

		/// <summary>
		/// Sends buffer.
		/// 
		/// DOES NOT DO ANY ENCRYPTION.
		/// </summary>
		/// <param name="buffer"></param>
		public virtual void SendRaw(byte[] buffer)
		{
			if (this.State == ClientState.Dead)
				return;

			//Log.Debug("out: " + BitConverter.ToString(buffer));

			try
			{
				this.Socket.Send(buffer);
			}
			catch (Exception ex)
			{
				Log.Error("Unable to send packet to '{0}'. ({1})", this.Address, ex.Message);
			}
		}

		/// <summary>
		/// Builds buffer from packet and passes it to <see cref="Send(byte[])"/>.
		/// </summary>
		/// <param name="packet"></param>
		public virtual void Send(Packet packet)
		{
			// Don't log internal packets
			//if (packet.Op < Op.Internal.ServerIdentify)
			//    Log.Debug("S: " + packet);

			this.Send(this.BuildPacket(packet));
		}

		/// <summary>
		/// Encrypts buffer and then passes it to <see cref="SendRaw(byte[])"/>.
		/// </summary>
		/// <param name="buffer"></param>
		/// <param name="protocolLength">The protocol header's length.
		/// 6 for ordinary packets</param>
		public virtual void Send(byte[] buffer, int protocolLength = 6)
		{
			this.Cipher.EncryptPacket(buffer, protocolLength, buffer.Length - protocolLength);

			this.SendRaw(buffer);
		}

		/// <summary>
		/// Builds packet, appending the overall header and checksum.
		/// </summary>
		/// <param name="packet"></param>
		/// <returns></returns>
		protected virtual byte[] BuildPacket(Packet packet)
		{
			var size = packet.GetSize();

			var result = new byte[6 + size]; // header + packet + checksum
			result[0] = 0x88;
			System.Buffer.BlockCopy(BitConverter.GetBytes(result.Length), 0, result, 1, sizeof(int));
			packet.Build(ref result, 6);

			return result;
		}

		/// <summary>
		/// Kills client connection.
		/// </summary>
		public virtual void Kill()
		{
			if (this.State != ClientState.Dead)
			{
				try
				{
					this.Socket.Shutdown(SocketShutdown.Both);
					this.Socket.Close();
				}
				catch
				{ }

				// Naturally, we have to clean up after killing somebody.
				this.CleanUp();

				this.State = ClientState.Dead;
			}
			else
			{
				Log.Warning("Client got killed multiple times." + Environment.NewLine + Environment.StackTrace);
			}
		}

		/// <summary>
		/// Takes care of client's remains (saving chars, etc)
		/// </summary>
		public virtual void CleanUp()
		{

		}
	}

	public enum ClientState { BeingChecked, LoggingIn, LoggedIn, Dead }
}
