//
// Created by 史志成 on 2018/5/3.
//
#include "test.h"
#include <string>
#include "sha512.h"
#include "iostream"
using namespace std;
int test(std::string file1,std::string file2){
    FILE* fp1=fopen(file1.c_str(),"r");
    FILE* fp2=fopen(file2.c_str(),"r");
    std::string str1=sha512file(fp1);
    std::string str2=sha512file(fp2);
    fclose(fp1);
    fclose(fp2);
    if (str1==str2)
        return 1;
    else
        return 0;
}
void procedure(){
    string file1;
    string file2;
    cout<<"请输入文件路径1："<<endl;
    cin>>file1;
    cout<<"请输入文件路径2："<<endl;
    cin>>file2;
    if (test(file1,file2))
        printf("文件相同\n");
    else
        printf("文件不同\n");
}
