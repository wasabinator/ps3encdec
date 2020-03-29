#ifndef _SECTOR_H_
#define _SECTOR_H_

#include "types.h"

void decrypt_sector(u8* sector, u64 sector_index, s32 sector_size, u8* zero_iv, u8* ata_k1, u8* ata_k2, u8* edec_k1, u8* edec_k2, BOOL is_phat, BOOL is_vflash);
void encrypt_sector(u8* sector, u64 sector_index, s32 sector_size, u8* zero_iv, u8* ata_k1, u8* ata_k2, u8* edec_k1, u8* edec_k2, BOOL is_phat, BOOL is_vflash);

#endif