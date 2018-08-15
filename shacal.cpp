//
// Created by 史志成 on 2018/4/10.
//
#include "shacal.h"
int static last_len;
const unsigned long SHACAL::SHACAL_W[64] = {//64个轮常数
        0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
        0x3956C25b, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
        0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
        0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
        0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
        0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
        0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
        0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
        0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
        0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
        0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
        0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
        0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
        0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
        0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
        0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
};

/**
 *功能：密钥划分，得到64个密钥字
 * @param digest 消息摘要
 *
 */
////////////////////////////////////////////////////////////////////////////////////
void SHACAL::div_key(const char *digest) {
    for (int j = 0; j < 16; ++j) {
        key[j] = digest[j] + SHACAL_W[j];
    }

    for (int j = 16; j < 64; ++j) {
        key[j] = SHACAL_F1(key[j - 2]) + key[j - 7] + SHACAL_F0(key[j - 15]) + key[j - 16];
        key[j] += SHACAL_W[j];
    }

}
/////////////////////////////////////////////////////////////////////////////////////////////
/**
 * 功能：加密block_nb数目分组的明文
 * @param message 明文首地址
 * @param block_nb 分组的数目
 */
void SHACAL::transform1(const unsigned char *message, unsigned int block_nb) {
    const unsigned char *sub_block = NULL;//当前分组的首指针
    uint32_t text[8];
    unsigned int blockLength = block_nb * 32;//当前读入内存明文的总长度,单位（字节）
    //分配密文存储空间
    unsigned char *out = (unsigned char *) malloc(blockLength);
    unsigned char *temp = out;
    for (int i = 0; i < block_nb; ++i) {//对block_nb个块进行加密
        sub_block = message + (i << 5);//sub_block 指针指向下一个分组的首地址，即移动32个字节
        temp = out + (i << 5);//temp移动到下一个密文分组
        for (int k = 0; k < 8; ++k) {//将256bit的明文存放在8个32位字中
            SHACAL_PACK32(sub_block + (k << 2), &text[k]);

        }
        ///////////////////////////////////////////////////////////////////////////
        uint32_t T1, T2;
        uint32_t a = text[0];
        uint32_t b = text[1];
        uint32_t c = text[2];
        uint32_t d = text[3];
        uint32_t e = text[4];
        uint32_t f = text[5];
        uint32_t g = text[6];
        uint32_t h = text[7];
        for (int j = 0; j < 64; ++j) {//64轮加密
            //  T1 = h + kryptos_shacal2_BSIG1(e) + kryptos_shacal2_CH(e, f, g) + key[j] + w[j];
            T1 = h + SIG1(e) + SHACAL_Ch(e, f, g) + key[j] + SHACAL_W[j];
            T2 = SIG0(a) + SHACAL_MAJ(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }
        text[0] = a;
        text[1] = b;
        text[2] = c;
        text[3] = d;
        text[4] = e;
        text[5] = f;
        text[6] = g;
        text[7] = h;
        ////////////////////////////////////////////////////////////////////////////
        for (int l = 0; l < 8; ++l) {//将得到的8个加密后的密文字装填到output中
            SHACAL_UNPACK32(text[l], &temp[l << 2]);//每填充一个字，指针移动4个字节
        }
    }
    //将加密后的数据块写入外存
    fwrite(out, sizeof(char), blockLength, to_path);
    free(out);
}

/**
 * 功能：解密block_nb分组数目的密文
 * @param message 明文指针
 * @param block_nb 分组数目
 */
void SHACAL::transform2(const unsigned char *message, unsigned int block_nb) {
    const unsigned char *sub_block = NULL;//当前分组的首指针
    uint32_t text[8];
    unsigned int blockLength = block_nb * 32;//当前读入内存明文的总长度,单位（字节）
    //分配密文存储空间
    unsigned char *out = (unsigned char *) malloc(blockLength);
    unsigned char *temp = out;
    for (int i = 0; i < block_nb; ++i) {//对block_nb个块进行加密
        sub_block = message + (i << 5);//sub_block 指针指向下一个分组的首地址，即移动32个字节
        temp = out + (i << 5);//temp移动到下一个密文分组
        for (int k = 0; k < 8; ++k) {//将256bit的明文存放在8个32位字中
            SHACAL_PACK32(sub_block + (k << 2), &text[k]);
        }
        ////////////////////////////////////////////////////////////////////
        uint32_t T1, T2;
        uint32_t a = text[0];
        uint32_t b = text[1];
        uint32_t c = text[2];
        uint32_t d = text[3];
        uint32_t e = text[4];
        uint32_t f = text[5];
        uint32_t g = text[6];
        uint32_t h = text[7];
        for (int j = 63; j >= 0; j--) {
            T1 = a;
            a = b;
            b = c;
            c = d;
            d = e;
            e = f;
            f = g;
            g = h;
            T2 = SIG0(a) + SHACAL_MAJ(a, b, c);
            T1 -= T2;
            d -= T1;
            h = T1 - (SIG1(e) + SHACAL_Ch(e, f, g) + key[j] + SHACAL_W[j]);
        }
        text[0] = a;
        text[1] = b;
        text[2] = c;
        text[3] = d;
        text[4] = e;
        text[5] = f;
        text[6] = g;
        text[7] = h;
        ///////////////////////////////////////////////////////////////////////////////
        for (int l = 0; l < 8; ++l) {//将得到的8个加密后的密文字装填到output中
            SHACAL_UNPACK32(text[l], &temp[l << 2]);//每填充一个字，指针移动4个字节
        }
    }

    //将加密后的数据块写入外存
    if (end_tag != 1)
        fwrite(out, sizeof(char), blockLength, to_path);
    else {
        int x = out[blockLength - 1];//得到最后一个分组的长度
        fwrite(out, sizeof(char), x, to_path);
    }
    free(out);
}

/**
 * 功能：加密所有完整的明文分组
 * 备注：这是transform1的上层模块
 * @param message 明文首地址
 * @param len 读入的字节数
 */
void SHACAL::update1(unsigned char *message, unsigned int len) {
    int block_nb = 32;//需要加密的分组的数目
    unsigned char *output = NULL;
    if (len == 1024) {//表明读满了32个分组，对这32个分组进行加密
        transform1(message, block_nb);
    } else {//表明未读满32个分组，同时表明最后一个分组已经读入内存中
        m_len = len % 32;//得到最后一个分组的长度,单位（字节）
        last_len=m_len;
        block_nb = len / 32;//最后一次读入内存操作中读入内存的分组数目减1
        transform1(message, block_nb);
        if (m_len != 0)//如果不需要填充
            final1(&message[block_nb << 5]);
    }
}

/**
 * 功能：加密最后一个明文分组
 * @param final_message 明文指针
 */
void SHACAL::final1(unsigned char *final_message) {
    unsigned char *buf = (unsigned char *) malloc(BLOCK_SIZE);
    memcpy(buf, final_message, m_len);//将明文拷贝至缓冲区中
    memset(buf + m_len, 0, BLOCK_SIZE - m_len);//填充0
    buf[BLOCK_SIZE - 1] = m_len;//将短分组的长度填入最后一个字节
    transform1(buf, 1);//加密最后一个短分组
}

/**
 * 功能：获得文件输入输出指针
 * @param in 输入路径
 * @param out 输出路径
 */
void SHACAL::getFilePoint(const char *in, const char *out) {
    SHACAL::from_path = std::fopen(in, "r");
    SHACAL::to_path = std::fopen(out, "w");
}

/**
 *功能：加密文件
 * @param in
 * @param out
 */
void encryptFile(std::string in, std::string out, std::string hashKey) {
    SHACAL ctx = SHACAL();
    ctx.div_key(hashKey.c_str());//划分密钥
    ctx.getFilePoint(in.c_str(), out.c_str());//由两个地址得到指针，并打开文件
    unsigned char buff[BUFSIZ];
    size_t len;
    /*BUFSIZ为1024
     * shacal-2的分组长度为256bit
     * 即每次读入32个分组
     */
    while ((len = std::fread(buff, sizeof(char), BUFSIZ, ctx.from_path)) > 0) {
        ctx.update1((unsigned char *) buff, len);//进行加密
    }
    //关闭文件指针
    std::fclose(ctx.from_path);
    std::fclose(ctx.to_path);
}

/**
 *功能：解密文件
 * @param in 加密文件路径
 * @param out 解密文件路径
 */
void decryptFile(std::string in, std::string out, std::string hashKey) {
    SHACAL ctx = SHACAL();
    ctx.end_tag = 0;//初始化末分组标记为0
    ctx.div_key(hashKey.c_str());//划分密钥
    ctx.getFilePoint(in.c_str(), out.c_str());//由两个地址得到指针，并打开文件
    unsigned char buff[BUFSIZ];
    size_t len;
    /*BUFSIZ为1024
     * shacal-2的分组长度为256bit
     * 即每次读入32个分组
     */
    while ((len = std::fread(buff, sizeof(char), BUFSIZ, ctx.from_path)) > 0) {
        ctx.update2((unsigned char *) buff, len);//进行解密
    }
    //关闭文件指针
    std::fclose(ctx.from_path);
    std::fclose(ctx.to_path);
}

/**
 * 功能：对长度为len的密文进行解密
 * @param message 密文指针
 * @param len 密文长度
 */
void SHACAL::update2(unsigned char *message, unsigned int len) {
    int block_nb = 32;//需要加密的分组的数目
    unsigned char *output = NULL;
    if (len == 1024) {//表明读满了32个分组，对这32个分组进行加密
        transform2(message, block_nb);
    } else {//表明未读满32个分组，同时表明最后一个分组已经读入内存中
        block_nb = len / 32;//处理前n-1个密文分组
        if (last_len != 0) {
            transform2(message, block_nb - 1);
            final2(&message[(block_nb - 1) << 5]);
        }else
            transform2(message,block_nb);

    }
}

/**
 * 功能：解密最后一个分组
 * @param final_message
 */
void SHACAL::final2(unsigned char *final_message) {
    end_tag = 1;//置末分组标记为1，表明当前处理的分组为最后一个分组
    unsigned char *buf = (unsigned char *) malloc(32);
    memcpy(buf, final_message, 32);//将明文拷贝至缓冲区中
    transform2(buf, 1);
}

