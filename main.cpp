#include <iostream>
#include "sha512.h"
#include "shacal.h"
#include <ctime>
#include "test.h"
#include "index.h"
using namespace std;
int main() {
    /*********************加解密文件*****************************************/
//    string hashPath1 = "abc";
//    string hashPath2 = "abc";
//    string messagePath = "/Users/shishisei/Desktop/1.qsv";
//    string encryptionPath = "/Users/shishisei/Desktop/encryption";
//    string decryptionPath = "/Users/shishisei/Desktop/2.qsv";
//    string hashKey = sha512(hashPath1);
//    auto begin = clock();
//    encryptFile(messagePath, encryptionPath, hashKey);
//    auto end1 = clock();
//    printf("加密时间: %d\n", (end1 - begin) / CLOCKS_PER_SEC);
//    hashKey = sha512(hashPath2);
//    decryptFile(encryptionPath, decryptionPath, hashKey);
//    auto end2 = clock();
//    printf("解密时间: %d\n", (end2 - end1) / CLOCKS_PER_SEC);
//    remove(encryptionPath.c_str());//删除加密后的文件
    /*********************************************************************/

    /**************测试文件是否相同***************************/
//    string messagePath = "/Users/shishisei/Desktop/1.docx";
//    string encryptionPath = "/Users/shishisei/Desktop/encryption";
//    string decryptionPath = "/Users/shishisei/Desktop/2.docx";
//    procedure(messagePath,decryptionPath);
    /*********************************************/

    /*************************演示*****************************************/
    index();
    /***********************************************************************/
}

