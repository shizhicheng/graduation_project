//
// Created by 史志成 on 2018/4/10.
//

#ifndef GRADUATION_PROJECT_SHACAL_H
#define GRADUATION_PROJECT_SHACAL_H

#include <string>
#include <cstring>
#include <fstream>
#include <stdint.h>

#ifndef SHACAL2_H
#define SHACAL2_H

void encryptFile(std::string in, std::string out, std::string hashKey);

void decryptFile(std::string in, std::string out, std::string hashKey);

class SHACAL {
public:

    void div_key(const char *digest);//密钥划分
    void update1(unsigned char *message, unsigned int len);//加密前n-1个分组
    void update2(unsigned char *message, unsigned int len);//解密前n-1个分组
    void transform1(const unsigned char *message, unsigned int block_nb);//加密已经读入的分组
    void transform2(const unsigned char *message, unsigned int block_nb);//解密已经读入的分组
    void final1(unsigned char *digest);//加密最后一个分组
    void getFilePoint(const char *in, const char *out);
    void final2(unsigned char *final_message);

protected:
    const static u_long SHACAL_W[64];//64个轮常数
    uint32_t key[64];//64个32位的轮密钥
    unsigned int m_len;//短分组的长度
public:
    FILE *from_path = nullptr;//要加密文件的文件指针
    FILE *to_path = nullptr;//加密后文件的文件指针
    int end_tag;//表明解密到最后一个分组
};

#define SHACAL_S(x, n) ( ( (x) >> (n) ) | ( (x) << ( (sizeof(x) << 3) - (n) ) ) )//循环右移
#define SHACAL_R(x, n)  ((x)>>(n)) //右移
#define SHACAL_F0(x)  ((SHACAL_S(x, 7)) ^ (SHACAL_S(x, 18)) ^ (SHACAL_R(x, 3)))
#define SHACAL_F1(x)  ((SHACAL_S(x, 17)) ^ (SHACAL_S(x, 19)) ^ (SHACAL_R(x, 10)))
#define SIG0(x)  ((SHACAL_S(x, 2)) ^ (SHACAL_S(x, 13)) ^ (SHACAL_S(x, 22)))
#define SIG1(x)  (SHACAL_S(x, 6) ^ SHACAL_S(x, 11) ^ SHACAL_S(x, 25))
#define SHACAL_Ch(x, y, z)  ((x & y) ^ (~(x) & z))
#define SHACAL_MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define BLOCK_SIZE 32
//将unsigned char 类型的str换成uint32类型的x字中
#define SHACAL_PACK32(str, x)                    \
{                                                \
        *(x) = ((uint32_t) *((str) + 3) << 24  )   \
             | ((uint32_t) *((str) + 2) << 16    )  \
             | ((uint32_t) *((str) + 1) << 8  )   \
             | ((uint32_t) *((str) + 0) << 0  );  \
}

//将32位的字装填到str数组中，这里str数组的类型为unsigned char
#define SHACAL_UNPACK32(x, str)                  \
{                                                \
    *((str) + 3) = (unsigned char) ((x) >> 24   );   \
    *((str) + 2) = (unsigned char) ((x) >> 16);          \
    *((str) + 1) = (unsigned char) ((x) >> 8);          \
    *((str) + 0) = (unsigned char) ((x) >> 0);          \
}
#endif
#endif //GRADUATION_PROJECT_SHACAL_H
