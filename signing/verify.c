/**
** To compile: 
** gcc -g -O2 -Wall -mmmx -msse2 -msse  -maes -mpreferred-stack-boundary=4  -m64 -march=native -o verify  verify.c 

 gcc  -fPIC -DOPENSSL_PIC -DZLIB -DOPENSSL_THREADS -D_REENTRANT -DDSO_DLFCN -DHAVE_DLFCN_H -DKRB5_MIT -m64 -DL_ENDIAN -Wall -O2 -g -pipe -Wall -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector-strong --param=ssp-buffer-size=4 -grecord-gcc-switches   -m64 -mtune=generic -Wa,--noexecstack -DPURIFY -DOPENSSL_IA32_SSE2 -DOPENSSL_BN_ASM_MONT -DOPENSSL_BN_ASM_MONT5 -DOPENSSL_BN_ASM_GF2m -DRC4_ASM -DSHA1_ASM -DSHA256_ASM -DSHA512_ASM -DMD5_ASM -DAES_ASM -DVPAES_ASM -DBSAES_ASM -DWHIRLPOOL_ASM -DGHASH_ASM -DECP_NISTZ256_ASM


**///compile using gcc and following arguments: -g;-O0;-Wall;-msse2;-msse;-march=native;-maes
#ifndef __AES_NI_H__
#define __AES_NI_H__

#include <time.h>
#include <stdio.h>
#include <string.h>   
#include <stdlib.h>
#include <immintrin.h>
#include <x86intrin.h>
//#include <linux/types.h> __u64
#include <emmintrin.h>   
#include <wmmintrin.h>


/* Define standard sized integers  */
#if defined(_MSC_VER) && (_MSC_VER < 1600)
	typedef unsigned __int8  uint8_t;
	typedef unsigned __int32 uint32_t;
	typedef unsigned __int64 uint64_t;
	typedef          __int64 int64_t;
#else
	#include <stdint.h>
#endif


/* Some helper functions */
#define rnds 10 //AES rounds
typedef __m128i block;
typedef struct { __m128i rd_key[11]; } AES_KEY;
#define xor_block(x,y)   _mm_xor_si128(x,y)
#define zero_block()    _mm_setzero_si128()

const static unsigned char aeskey[16] = {0};
static AES_KEY const_key;
static block current_key, current_state, update_zero, update_one;

/********************************************************************/
// AES Key Expansion
// Sources: OCB Version 3 Reference Code (Optimized C)  
// https://www.cs.ucdavis.edu/~rogaway/ocb/news/code/ocb.c
//

#define EXPAND_ASSIST(v1,v2,v3,v4,shuff_const,aes_const)                    \
  do{                                                                       \
    v2 = _mm_aeskeygenassist_si128(v4,aes_const);                           \
    v3 = _mm_castps_si128(_mm_shuffle_ps(_mm_castsi128_ps(v3),              \
                                         _mm_castsi128_ps(v1), 16));        \
    v1 = _mm_xor_si128(v1,v3);                                              \
    v3 = _mm_castps_si128(_mm_shuffle_ps(_mm_castsi128_ps(v3),              \
                                         _mm_castsi128_ps(v1), 140));       \
    v1 = _mm_xor_si128(v1,v3);                                              \
    v2 = _mm_shuffle_epi32(v2,shuff_const);                                 \
    v1 = _mm_xor_si128(v1,v2);                                              \
  } while(0)


void AES_128_Key_Expansion(const unsigned char *userkey, void *key)
{
    __m128i x0,x1,x2;
    __m128i *kp = (__m128i *)key;
    kp[0] = x0 = _mm_loadu_si128((__m128i*)userkey);
    x2 = _mm_setzero_si128();
    EXPAND_ASSIST(x0,x1,x2,x0,255,1);   kp[1]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,2);   kp[2]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,4);   kp[3]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,8);   kp[4]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,16);  kp[5]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,32);  kp[6]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,64);  kp[7]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,128); kp[8]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,27);  kp[9]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,54);  kp[10] = x0;
}
#undef EXPAND_ASSIST



//-----------some helper functions------------------------------

//Load 14-byte log data after the 2-byte counter
#define gen_logging_blk(log,ctr) _mm_insert_epi16(_mm_loadu_si128(log), ctr, 0)
//Generate 7-block MAC1 inputs
#define frist_blks(cblk_1, cblk_2, cblk_3, cblk_4, cblk_5, cblk_6, cblk_7, cblk_8, log_msg) \
    do{                                                                    \
		cblk_1[0]   = _mm_srli_si128(_mm_loadu_si128((block*)log_msg), 2); \
		cblk_2[0]   = _mm_srli_si128(_mm_loadu_si128((block*)log_msg), 2);  \
		cblk_3[0]   = _mm_srli_si128(_mm_loadu_si128((block*)log_msg), 2);  \
		cblk_4[0]   = _mm_srli_si128(_mm_loadu_si128((block*)log_msg), 2); \
		cblk_5[0]   = _mm_srli_si128(_mm_loadu_si128((block*)log_msg), 2);  \
		cblk_6[0]   = _mm_srli_si128(_mm_loadu_si128((block*)log_msg), 2);  \
		cblk_7[0]   = _mm_srli_si128(_mm_loadu_si128((block*)log_msg), 2);  \
		cblk_8[0]   = _mm_srli_si128(_mm_loadu_si128((block*)log_msg), 2);  \
		cblk_1[0]  = _mm_insert_epi16(cblk_1[0], 0x0001, 0); \
		cblk_1[0]  = _mm_insert_epi16(cblk_1[0], 0x0001, 0); \
		cblk_1[0]  = _mm_insert_epi16(cblk_1[0], 0x0001, 0); \
		cblk_1[0]  = _mm_insert_epi16(cblk_1[0], 0x0001, 0); \
		cblk_1[0]  = _mm_insert_epi16(cblk_1[0], 0x0001, 0); \
		cblk_1[0]  = _mm_insert_epi16(cblk_1[0], 0x0001, 0); \
		cblk_1[0]  = _mm_insert_epi16(cblk_1[0], 0x0001, 0); \
	} while(0)

//Generate 7-block MAC1 inputs
#define gen_7_blks(cipher_blks,log_msg, counter)                            \
    do{                                                                    \
		cipher_blks[1]  = gen_logging_blk((block*)(log_msg+12),counter+2); \
		cipher_blks[2]  = gen_logging_blk((block*)(log_msg+26),counter+3); \
		cipher_blks[3]  = gen_logging_blk((block*)(log_msg+40),counter+4); \
		cipher_blks[4]  = gen_logging_blk((block*)(log_msg+54),counter+5); \
		cipher_blks[5]  = gen_logging_blk((block*)(log_msg+68),counter+6); \
		cipher_blks[6]  = gen_logging_blk((block*)(log_msg+82),counter+7); \
		cipher_blks[7]  = gen_logging_blk((block*)(log_msg+96),counter+8); \
	} while(0)

//AES pre-round 8 blocks
#define prernd_8(cipher_blks, key)                       \
	do{                                                  \
		cipher_blks[0] = xor_block(cipher_blks[0], key); \
		cipher_blks[1] = xor_block(cipher_blks[1], key); \
		cipher_blks[2] = xor_block(cipher_blks[2], key); \
		cipher_blks[3] = xor_block(cipher_blks[3], key); \
		cipher_blks[4] = xor_block(cipher_blks[4], key); \
		cipher_blks[5] = xor_block(cipher_blks[5], key); \
		cipher_blks[6] = xor_block(cipher_blks[6], key); \
		cipher_blks[7] = xor_block(cipher_blks[7], key); \
	} while(0)
	
//AES Pre-round 4 blocks
#define prernd_4(cipher_blks,sign_keys) 			       \
  do{                                                      \
    cipher_blks[0] = xor_block(cipher_blks[0], sign_keys); \
    cipher_blks[1] = xor_block(cipher_blks[1], sign_keys); \
    cipher_blks[2] = xor_block(cipher_blks[2], sign_keys); \
    cipher_blks[3] = xor_block(cipher_blks[3], sign_keys); \
  } while(0)


//XOR 8 cipher blocks
#define tag_8_xor(tag_blks,cipher_blks)                                                                       \
  do{                                                                                                              \
	tag_blks[0] =xor_block(xor_block(cipher_blks[0], cipher_blks[1]), xor_block(cipher_blks[2], cipher_blks[3]));  \
	tag_blks[1] =xor_block(xor_block(cipher_blks[4], cipher_blks[5]), xor_block(cipher_blks[6], cipher_blks[7]));  \
	tag_blks[2] =xor_block(tag_blks[2], xor_block(tag_blks[0], tag_blks[1]));                                      \
  } while(0)






#define enc_8(cipher_blks, key)                                 \
	do{                                                         \
		cipher_blks[0] = _mm_aesenc_si128(cipher_blks[0], key); \
		cipher_blks[1] = _mm_aesenc_si128(cipher_blks[1], key); \
		cipher_blks[2] = _mm_aesenc_si128(cipher_blks[2], key); \
		cipher_blks[3] = _mm_aesenc_si128(cipher_blks[3], key); \
		cipher_blks[4] = _mm_aesenc_si128(cipher_blks[4], key); \
		cipher_blks[5] = _mm_aesenc_si128(cipher_blks[5], key); \
		cipher_blks[6] = _mm_aesenc_si128(cipher_blks[6], key); \
		cipher_blks[7] = _mm_aesenc_si128(cipher_blks[7], key); \
  	}while(0)



#define enc_4(cipher_blks, key)                                 \
	do{                                                         \
		cipher_blks[0] = _mm_aesenc_si128(cipher_blks[0], key); \
		cipher_blks[1] = _mm_aesenc_si128(cipher_blks[1], key); \
		cipher_blks[2] = _mm_aesenc_si128(cipher_blks[2], key); \
		cipher_blks[3] = _mm_aesenc_si128(cipher_blks[3], key); \
  	}while(0)

#define enc_2(cipher_blks, key)                                 \
	do{                                                         \
		cipher_blks[0] = _mm_aesenc_si128(cipher_blks[0], key); \
		cipher_blks[1] = _mm_aesenc_si128(cipher_blks[1], key); \
  	}while(0)


#define aes_single(cipher_blks, sched)                               \
	do{                                                              \
		cipher_blks[0] = _mm_aesenc_si128(cipher_blks[0], sched[1]); \
		cipher_blks[0] = _mm_aesenc_si128(cipher_blks[0], sched[2]); \
		cipher_blks[0] = _mm_aesenc_si128(cipher_blks[0], sched[3]); \
		cipher_blks[0] = _mm_aesenc_si128(cipher_blks[0], sched[4]); \
		cipher_blks[0] = _mm_aesenc_si128(cipher_blks[0], sched[5]); \
		cipher_blks[0] = _mm_aesenc_si128(cipher_blks[0], sched[6]); \
		cipher_blks[0] = _mm_aesenc_si128(cipher_blks[0], sched[7]); \
		cipher_blks[0] = _mm_aesenc_si128(cipher_blks[0], sched[8]); \
		cipher_blks[0] = _mm_aesenc_si128(cipher_blks[0], sched[9]); \
		cipher_blks[0] =_mm_aesenclast_si128(cipher_blks[0], sched[10]);\
	} while(0)




#define AES_ECB_2(cipher_blks, sched, sign_keys)   \
	do{                                        	   \
		cipher_blks[0] =_mm_xor_si128(cipher_blks[0], sign_keys); \
		cipher_blks[1] =_mm_xor_si128(cipher_blks[1], sign_keys); \
		enc_2(cipher_blks, sched[2]);              \
		enc_2(cipher_blks, sched[3]);              \
		enc_2(cipher_blks, sched[4]);              \
		enc_2(cipher_blks, sched[5]);              \
		enc_2(cipher_blks, sched[6]);              \
		enc_2(cipher_blks, sched[7]);              \
		enc_2(cipher_blks, sched[8]);              \
		enc_2(cipher_blks, sched[9]);              \
		cipher_blks[0] =_mm_aesenclast_si128(cipher_blks[0], sched[10]); \
		cipher_blks[1] =_mm_aesenclast_si128(cipher_blks[1], sched[10]); \
	}while (0)




#define AES_ECB_8(cipher_blks, sched, sign_keys)   \
	do{                                        	   \
		prernd_8(cipher_blks,sign_keys);           \
		enc_8(cipher_blks, sched[1]);              \
		enc_8(cipher_blks, sched[2]);              \
		enc_8(cipher_blks, sched[3]);              \
		enc_8(cipher_blks, sched[4]);              \
		enc_8(cipher_blks, sched[5]);              \
		enc_8(cipher_blks, sched[6]);              \
		enc_8(cipher_blks, sched[7]);              \
		enc_8(cipher_blks, sched[8]);              \
		enc_8(cipher_blks, sched[9]);              \
		cipher_blks[0] =_mm_aesenclast_si128(cipher_blks[0], sched[10]); \
		cipher_blks[1] =_mm_aesenclast_si128(cipher_blks[1], sched[10]); \
		cipher_blks[2] =_mm_aesenclast_si128(cipher_blks[2], sched[10]); \
		cipher_blks[3] =_mm_aesenclast_si128(cipher_blks[3], sched[10]); \
		cipher_blks[4] =_mm_aesenclast_si128(cipher_blks[4], sched[10]); \
		cipher_blks[5] =_mm_aesenclast_si128(cipher_blks[5], sched[10]); \
		cipher_blks[6] =_mm_aesenclast_si128(cipher_blks[6], sched[10]); \
		cipher_blks[7] =_mm_aesenclast_si128(cipher_blks[7], sched[10]); \
	}while (0)






//*********************** end of help functions *************************************


/** Initial:
*** Expand AES round keys
*** Genreate first signing key and state pair 
**/
static void crypto_int(void)
{
	int s_0[4];/* initial State */
	block mask, init_pair[2];
	for(i=0;i<4;i++) s_0[i] = 1;
	block * sched;
	AES_128_Key_Expansion(aeskey,&const_key); //expand aes round keys
	sched = ((block *)(const_key.rd_key)); //point to AES round keys
	update_zero = zero_block();
	update_one = _mm_setr_epi32(0x0001, 0x0000, 0x0000, 0x0000);
	init_pair[0] = zero_block();/*Update 0 for state, 1 for key*/
	init_pair[1] = _mm_setr_epi32(0x0001, 0x0000, 0x0000, 0x0000);
	mask = _mm_xor_si128(sched[0], *(block *)s_0);/*xor the intial state with the aes  fixed key*/
	AES_ECB_2(init_pair, sched, mask);
	current_state = xor_block(init_pair[0], *(block *)s_0);
	current_key = xor_block(init_pair[1], *(block *)s_0);
}




/**  
* Input @log_msg: a log data, 
* Computing block format: a block(16 bytes) contains "<i>||M_i",  
*                         2 bytes counter(<i>) and 14 bytes log data(M_i)
* Output: T(128-byte tag), user can modify the tag length in "audit_log_end"
**/
#if 0
uint64_t verify_core( char *log_msg)
{
	size_t msg_len = strlen(log_msg);
	//size_t msg_len = len;
	uint16_t i, remaining , counter = 0;  /*now the max log size is 8192 KB*/
	block * sched, *aes_blks, *out;
	block mask, cipher_blks[8], tag_blks[3];
	int nblks;
	uint64_t proof[2];
	union { uint16_t u16[8]; uint8_t u8[16]; block bl; } tmp;//tmp: used for padding the last block
	nblks = (msg_len/112); 
	remaining =(__u16)(msg_len%112);
	sched = ((block *)(const_key.rd_key)); //point to AES round keys
	out = ((block *)(proof));
	aes_blks = cipher_blks;
	tag_blks[2] = current_key;
	
	mask =_mm_xor_si128(sched[0], current_key);/*xor the signing key with the aes  fixed key*/
	
	if(nblks){//start 8 blocks parallel computing 
		cipher_blks[0]  = _mm_srli_si128(_mm_loadu_si128((block*)log_msg), 2); 
		cipher_blks[0]  = _mm_insert_epi16(cipher_blks[0], counter+1, 0);
		gen_7_blks(cipher_blks,log_msg,counter);
		//AES_ECB_8(cipher_blks,sched, mask);
		tag_8_xor(tag_blks,cipher_blks);
		counter +=8;
		log_msg +=110;/*112-byte computed, apply 110-byte, leaving 2-byte overwrote by counter*/
		--nblks;
		while(nblks){
			cipher_blks[0]  = gen_logging_blk((block*)log_msg, counter+1); 
			gen_7_blks(cipher_blks,log_msg,counter);
			//AES_ECB_8(cipher_blks,sched, mask);
			tag_8_xor(tag_blks,cipher_blks);
			counter +=8;
			log_msg +=110;
			--nblks;
		}
	}//end of nblks	
    if (remaining){
		if(remaining >=56){//4-block, 4*14=56 bytes log data
			cmpt_4_blks(aes_blks,counter, log_msg, sched, mask);
			tag_blks[0] = xor_block( xor_block(aes_blks[0], aes_blks[1]), xor_block(aes_blks[2], aes_blks[3])); 
			tag_blks[2] = xor_block(tag_blks[2], tag_blks[0]);
			remaining -= 56;
			counter +=4;
			log_msg +=54;/*56-byte computed, apply 54-byte, leaving 2-byte overwrote by counter*/
		}
		if (remaining >= 28) {//2-block, 2*14=28 bytes log data
			cmpt_2_blks(aes_blks,counter, log_msg, sched, mask);
			tag_blks[2] = xor_block(xor_block(aes_blks[0], aes_blks[1]), tag_blks[2]); 
			remaining -= 28;
			counter +=2;
			log_msg +=26;/*28-byte computed, apply 26-byte, leaving 2-byte overwrote by counter*/
		}
		if (remaining >= 14) {//1-block 14 bytes log data
			cmpt_a_blk(&aes_blks[0],counter, log_msg, sched, mask);
			tag_blks[2] = xor_block(tag_blks[2], aes_blks[0]);
			remaining -= 14;
			counter +=1;
			log_msg +=12;/*14-byte computed, apply 12-byte, leaving 2-byte overwrote by counter*/
		}
		if (remaining){
			if (counter)  log_msg +=2;
			counter += (14-remaining);
			//*last = zero_block();
			//for(i=0;i<remaining;i++) pad[i+2]=log_msg[i];
			//*last = xor_block(*last, mask);
			//AES_single(last, sched);
			//tag_blks[2] = xor_block(tag_blks[2], *last);
		}
    }//end of remaining
	//next[0] = update_mask;
	//next[1] = xor_block(*one, update_mask);
	//AES_ECB_2(next, sched);
	//current_key = xor_block(next[0], current_state);
	//current_state = xor_block(next[1], current_state);
	return proof[0];
}
#endif

#if 1
void my_test( char *log_msg)
{
	//size_t msg_len = strlen(log_msg);
	int i; 
	uint16_t remaining , counter = 0; 
	block * sched, *aes_blks, *out;
	block mask, tag_blks[3];
	block cblk_1[8], cblk_2[8],cblk_3[8],cblk_4[8];
	block cblk_5[8], cblk_6[8],cblk_7[8],cblk_8[8];
	int nblks;
	sched = ((block *)(const_key.rd_key)); //point to AES round keys

	frist_blks(cblk_1, cblk_2, cblk_3, cblk_4, cblk_5, cblk_6, cblk_7, cblk_8, log_msg);
	gen_7_blks(cblk_1,log_msg,counter);
	gen_7_blks(cblk_2,log_msg,counter);
	gen_7_blks(cblk_3,log_msg,counter);
	gen_7_blks(cblk_4,log_msg,counter);
	gen_7_blks(cblk_5,log_msg,counter);
	gen_7_blks(cblk_6,log_msg,counter);
	gen_7_blks(cblk_7,log_msg,counter);
	
	AES_ECB_8(cblk_1,sched, sched[0]);
	AES_ECB_8(cblk_2,sched, sched[0]);

	AES_ECB_8(cblk_3,sched, sched[0]);
	AES_ECB_8(cblk_4,sched, sched[0]);

	AES_ECB_8(cblk_5,sched, sched[0]);
	AES_ECB_8(cblk_6,sched, sched[0]);

	AES_ECB_8(cblk_7,sched, sched[0]);
	AES_ECB_8(cblk_8,sched, sched[0]);
}
#endif 





#undef gen_7_blks
#undef prernd_8
#undef prernd_4
#undef tag_8_xor




int ITERATIONS;
int len =256;


int main(int argc, char* argv[]){

    u_char str[8192];
	u_char cipher[8192];
	int i,j, p, my_speed;
	struct timespec start, end;
	long long  my_time;

	uint64_t tag[8];
	clockid_t id = CLOCK_REALTIME;
	union { uint64_t u64[2];  block bl; } vtag[8];

	if (argc >= 2) ITERATIONS = atoi(argv[1]); 
	else ITERATIONS = 500000;
	

	crypto_int();
	memset(str,'a',(len));
	u_int blks=16;

	clock_gettime(id, &start);

	for(j=0;j<ITERATIONS;j++){			
		#if 0
		vtag[0].bl = verify_core(log_message_1);
		vtag[1].bl = verify_core(log_message_2);
		vtag[2].bl = verify_core(log_message_3);
		vtag[3].bl = verify_core(log_message_4);
		vtag[4].bl = verify_core(log_message_5);
		vtag[5].bl = verify_core(log_message_6);
		vtag[6].bl = verify_core(log_message_7);
		vtag[7].bl = verify_core(log_message_8);

		for(i=0;i<8;i++){
			if (vtag[i]-tag[i]!=0){
				printf("Failed verification for\n");
				break;
			}
		}
		#endif
		my_test(str);
		//encrypt_ecb128(16, str, cipher);
	
	}
	clock_gettime(id,&end);
	
	my_time = ( (long long)(end.tv_sec - start.tv_sec))*1000000000 + (end.tv_nsec - start.tv_nsec);
	my_time = my_time/((long long )(ITERATIONS*8));
	my_speed = (int)((long long )len*1000000000)/((long long)(my_time*1048576));
	printf("My verification time = %lld (ns), throughput = MB/s\n", my_time/(ITERATIONS*8));



	return 0;

}
#endif