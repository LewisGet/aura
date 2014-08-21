// Copyright (c) Aura development team - Licensed under GNU GPL
// For more information, see license file in the main folder

using System;
using Aura.Shared.Util;

namespace Aura.Shared.Network
{
	/// <summary>
	/// Normal Mabi server (Login, Channel).
	/// </summary>
	/// <typeparam name="TClient"></typeparam>
	public class DefaultServer<TClient> : BaseServer<TClient> where TClient : BaseClient, new()
	{
		protected override int GetPacketLength(byte[] buffer, int ptr)
		{
			// <0x??><int:length><...>
			return
				(buffer[ptr + 1] << 0) +
				(buffer[ptr + 2] << 8) +
				(buffer[ptr + 3] << 16) +
				(buffer[ptr + 4] << 24);
		}

		protected override void HandleBuffer(TClient client, byte[] buffer)
		{
			Log.Info(BitConverter.ToString(buffer));

			var length = buffer.Length;

			// Not enabled in R61
			if (false)
			{
				// Cut 4 bytes at the end (checksum?)
				Array.Resize(ref buffer, length -= 4);

				// Write new length into the buffer.
				BitConverter.GetBytes(length)
					.CopyTo(buffer, 1);
			}

			client.Cipher.DecryptPacket(buffer, 6, length - 6);

			//Log.Debug("in:  " + BitConverter.ToString(buffer));

			// Flag 1 is a ping or something, encode and send back.
			if (buffer[5] == 0x01)
			{
				BitConverter.GetBytes(BitConverter.ToUInt32(buffer, 6) ^ 0x98BADCFE).CopyTo(buffer, 6);

				client.SendRaw(buffer);
			}
			else
			{
				// First packet, skip challenge and send success msg.
				if (client.State == ClientState.BeingChecked)
				{
					var c_success = new byte[] { 0x88, 0x07, 0x00, 0x00, 0x00, 0x00, 0x07 };

					client.Send(c_success);

					client.State = ClientState.LoggingIn;
				}
				// Actual packets
				else
				{
					// Start reading after the protocol header
					var packet = new Packet(buffer, 6);

					//Logger.Debug(packet);

					try
					{
						this.Handlers.Handle(client, packet);
					}
					catch (Exception ex)
					{
						Log.Exception(ex, "There has been a problem while handling '{0:X4}'.", packet.Op);
					}
				}
			}
		}

		protected override void OnClientConnected(TClient client)
		{
			// Send seed
			client.SendRaw(BitConverter.GetBytes(0x41757261)); // 0xAura;

			base.OnClientConnected(client);
		}
	}
}
