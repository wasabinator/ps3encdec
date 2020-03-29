#include "sector.h"
#include "aes.h"
#include "aes_xts.h"

/*! Swap u16 endianness. */
static void _es16_buffer(u8* buf, u32 length)
{
	u16* ptr = (u16*)buf;
	u32 i;

	for (i = 0; i < length / 2; i++)
		ptr[i] = _ES16(ptr[i]);
}

void decrypt_sector(u8* sector, u64 sector_index, s32 sector_size, u8* zero_iv, u8* ata_k1, u8* ata_k2, u8* edec_k1, u8* edec_k2, BOOL is_phat, BOOL is_vflash) {
	aes_xts_ctxt_t xts_ctxt;
	aes_context aes_ctxt;

	//Decrypt sector.
	if (is_vflash == TRUE)
	{
		if (is_phat == TRUE)
		{
			//Set key for AES-CBC
			aes_setkey_dec(&aes_ctxt, edec_k1, 128);
			//Decrypt CBC sector.
			memset(zero_iv, 0, 0x10);
			aes_crypt_cbc(&aes_ctxt, AES_DECRYPT, sector_size, zero_iv, sector, sector);
			//XOR initial block in sector with sector index value.
			sector[0x8] ^= (sector_index >> 56 & 0xFF);
			sector[0x9] ^= (sector_index >> 48 & 0xFF);
			sector[0xA] ^= (sector_index >> 40 & 0xFF);
			sector[0xB] ^= (sector_index >> 32 & 0xFF);
			sector[0xC] ^= (sector_index >> 24 & 0xFF);
			sector[0xD] ^= (sector_index >> 16 & 0xFF);
			sector[0xE] ^= (sector_index >> 8 & 0xFF);
			sector[0xF] ^= (sector_index & 0xFF);
		}
		else
		{
			//Init AES-XTS context.
			aes_xts_init(&xts_ctxt, AES_DECRYPT, edec_k1, edec_k2, 128);
			//Decrypt XTS sector.
			aes_xts_crypt(&xts_ctxt, sector_index, sector_size, sector, sector);
		}
	}
	else
	{
		if (is_phat == TRUE)
		{
			//Swap endian for ata only.				
			_es16_buffer(sector, sector_size);
			//Set key for AES-CBC
			aes_setkey_dec(&aes_ctxt, ata_k1, 192);
			//Decrypt CBC sector.
			memset(zero_iv, 0, 0x10);
			aes_crypt_cbc(&aes_ctxt, AES_DECRYPT, sector_size, zero_iv, sector, sector);
		}
		else
		{
			//Swap endian for ata only.
			_es16_buffer(sector, sector_size);
			//Init AES-XTS context.
			aes_xts_init(&xts_ctxt, AES_DECRYPT, ata_k1, ata_k2, 128);
			//Decrypt XTS sector.
			aes_xts_crypt(&xts_ctxt, sector_index, sector_size, sector, sector);
		}
	}
}

void encrypt_sector(u8* sector, u64 sector_index, s32 sector_size, u8* zero_iv, u8* ata_k1, u8* ata_k2, u8* edec_k1, u8* edec_k2, BOOL is_phat, BOOL is_vflash) {
	aes_xts_ctxt_t xts_ctxt;
	aes_context aes_ctxt;

	//Encrypt sector.
	if (is_vflash == TRUE)
	{
		if (is_phat == TRUE)
		{
			//XOR initial block in sector with sector index value.
			sector[0x8] ^= (sector_index >> 56 & 0xFF);
			sector[0x9] ^= (sector_index >> 48 & 0xFF);
			sector[0xA] ^= (sector_index >> 40 & 0xFF);
			sector[0xB] ^= (sector_index >> 32 & 0xFF);
			sector[0xC] ^= (sector_index >> 24 & 0xFF);
			sector[0xD] ^= (sector_index >> 16 & 0xFF);
			sector[0xE] ^= (sector_index >> 8 & 0xFF);
			sector[0xF] ^= (sector_index & 0xFF);
			//Set key for AES-CBC
			aes_setkey_enc(&aes_ctxt, edec_k1, 128);
			//Encrypt CBC sector.
			memset(zero_iv, 0, 0x10);
			aes_crypt_cbc(&aes_ctxt, AES_ENCRYPT, sector_size, zero_iv, sector, sector);
		}
		else
		{
			//Init AES-XTS context.
			aes_xts_init(&xts_ctxt, AES_ENCRYPT, edec_k1, edec_k2, 128);
			//Encrypt XTS sector.
			aes_xts_crypt(&xts_ctxt, sector_index, sector_size, sector, sector);
		}
	}
	else
	{
		if (is_phat == TRUE)
		{
			//Set key for AES-CBC
			aes_setkey_enc(&aes_ctxt, ata_k1, 192);
			//Encrypt CBC sector.
			memset(zero_iv, 0, 0x10);
			aes_crypt_cbc(&aes_ctxt, AES_ENCRYPT, sector_size, zero_iv, sector, sector);
			//Swap endian for ata only.				
			_es16_buffer(sector, sector_size);
		}
		else
		{
			//Init AES-XTS context.
			aes_xts_init(&xts_ctxt, AES_ENCRYPT, ata_k1, ata_k2, 128);
			//Encrypt XTS sector.
			aes_xts_crypt(&xts_ctxt, sector_index, sector_size, sector, sector);
			//Swap endian for ata only.
			_es16_buffer(sector, sector_size);
		}
	}
}
