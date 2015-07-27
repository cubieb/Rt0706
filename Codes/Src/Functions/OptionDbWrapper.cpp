#include "SystemInclude.h"

#include <libxml/parser.h>
#include <libxml/tree.h>

using namespace std;

class XmlDocDelter
{
public:
    XmlDocDelter()
    {}

    void operator()(xmlDocPtr doc) const
    {
        xmlFreeDoc(doc);
    }
};

//const char* XmlFileName = "../XmlFiles/C++SdkIncludeDir.xml";
const char* XmlFileName = "../XmlFiles/CreatedXml.xml";

bool CreaeXmlDoc()
{
    //定义文档和节点指针
    shared_ptr<xmlDoc> doc(xmlNewDoc((xmlChar*)"1.0"), XmlDocDelter());

    xmlNodePtr root_node = xmlNewNode(nullptr,(xmlChar*)"root");

    //设置根节点
    xmlDocSetRootElement(doc.get(),root_node);

    //在根节点中直接创建叶子节点
    xmlNewTextChild(root_node, nullptr, (xmlChar*)"newNode1", (xmlChar*)"newNode1 content");
    xmlNewTextChild(root_node, nullptr, (xmlChar*)"newNode2", (xmlChar*)"newNode2 content");
    xmlNewTextChild(root_node, nullptr, (xmlChar*)"newNode3", (xmlChar*)"newNode3 content");

    //创建一个节点，设置其内容和属性，然后加入根结点
    xmlNodePtr node = xmlNewNode(nullptr,(xmlChar*)"node2");
    xmlNodePtr content = xmlNewText((xmlChar*)"NODE CONTENT");

    xmlAddChild(root_node,node);
    xmlAddChild(node,content);
    xmlNewProp(node,(xmlChar*)"attribute",(xmlChar*)"yes");

    //创建一个儿子和孙子节点
    node = xmlNewNode(nullptr, (xmlChar*) "son");
    xmlAddChild(root_node,node);
    xmlNodePtr grandson = xmlNewNode(nullptr, (xmlChar*)"grandson");
    xmlAddChild(node,grandson);
    xmlAddChild(grandson, xmlNewText((xmlChar*)"This is a grandson node"));

    //存储xml文档
    int ret = xmlSaveFile(XmlFileName, doc.get());
    if (ret == -1)
    {
        cout << "Create XmlFile failed!" << endl;
        return false;
    }

    return true;
}