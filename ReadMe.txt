1 版本控制服务器路径
Svn Repository: http://code.taobao.org/svn/Rt0706/trunk
Git Repository: https://github.com/cd01220/Rt0706.git

2 代码目录结构
 2.1）所有代码都存在于Codes目录下。
 2.2）Codes/Include/Functions 用于存放功能模块需要被其他模块引用的.h文件，本目录所有代码都属于Router命名空间。
 2.3）Codes/Include/Public 用于存放其他项目也可能用到的通用库的.h文件，本目录所有代码都属于缺省命名空间。
 2.4）Codes/Src/Functions 用于存放功能模块.cpp文件，本目录所有代码都属于Router命名空间。
 2.5）Codes/Src/Public 用于存放其他项目也可能用到的通用库的.cpp文件， 本目录所有代码都属于缺省命名空间。


2 tag history.
tag1:  (svn version: 166) 
    1 为了使用ACE提供的软件框架和设计模式, 特将之前的版本打一个tag保存起来.
