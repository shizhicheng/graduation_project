//
// Created by 史志成 on 2018/5/3.
//
#include "string"
#include "iostream"
#include "sha512.h"
#include "shacal.h"
#include "test.h"
#include <ctime>
using namespace std;
void index(){
    string messagePath;
    string encryptionPath;
    string decryptionPath;
    string pwd;
    string hashKey;
    int x = 0;
    while (x != 4) {
        //界面
        cout<<"**********************************************"<<endl;
        cout << "*基于SHA-512及SHACAL-2算法的加密系统*" << endl;
        cout << "*请选择功能：" << endl;
        cout << "*1、加密" << endl;
        cout << "*2、解密" << endl;
        cout << "*3、测试" << endl;
        cout << "*4、退出" << endl;
        cout<<"**********************************************"<<endl;
        //接受输入
        if (cin >> x && x != 1 && x != 2 && x != 3 && x != 4) {
            cout << "请重新输入" << endl;
            continue;
        }
        if (x == 4)
            break;
        if (x == 1) {//加密过程
            cout << "请输入明文路径：" << endl;
            cin >> messagePath;
            cout << "请输入密文路径：" << endl;
            cin >> encryptionPath;
            cout << "请输入密码" << endl;
            cin >> pwd;
            hashKey = sha512(pwd);
            auto begin = clock();
            encryptFile(messagePath, encryptionPath, hashKey);
            auto end1 = clock();
            cout << "加密时间:" << (end1 - begin) / CLOCKS_PER_SEC << endl;
        } else if(x==2) {//解密过程
            cout << "请输入密文路径：" << endl;
            cin >> encryptionPath;
            cout << "请输入解密路径：" << endl;
            cin >> decryptionPath;
            cout << "请输入密码" << endl;
            cin >> pwd;
            hashKey = sha512(pwd);
            auto begin = clock();
            decryptFile(encryptionPath, decryptionPath, hashKey);
            auto end1 = clock();
            cout << "解密时间:" << (end1 - begin) / CLOCKS_PER_SEC << endl;
        }else
            procedure();

    }

}
