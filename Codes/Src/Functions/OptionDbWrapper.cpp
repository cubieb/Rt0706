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
    //�����ĵ��ͽڵ�ָ��
    shared_ptr<xmlDoc> doc(xmlNewDoc((xmlChar*)"1.0"), XmlDocDelter());

    xmlNodePtr root_node = xmlNewNode(nullptr,(xmlChar*)"root");

    //���ø��ڵ�
    xmlDocSetRootElement(doc.get(),root_node);

    //�ڸ��ڵ���ֱ�Ӵ���Ҷ�ӽڵ�
    xmlNewTextChild(root_node, nullptr, (xmlChar*)"newNode1", (xmlChar*)"newNode1 content");
    xmlNewTextChild(root_node, nullptr, (xmlChar*)"newNode2", (xmlChar*)"newNode2 content");
    xmlNewTextChild(root_node, nullptr, (xmlChar*)"newNode3", (xmlChar*)"newNode3 content");

    //����һ���ڵ㣬���������ݺ����ԣ�Ȼ���������
    xmlNodePtr node = xmlNewNode(nullptr,(xmlChar*)"node2");
    xmlNodePtr content = xmlNewText((xmlChar*)"NODE CONTENT");

    xmlAddChild(root_node,node);
    xmlAddChild(node,content);
    xmlNewProp(node,(xmlChar*)"attribute",(xmlChar*)"yes");

    //����һ�����Ӻ����ӽڵ�
    node = xmlNewNode(nullptr, (xmlChar*) "son");
    xmlAddChild(root_node,node);
    xmlNodePtr grandson = xmlNewNode(nullptr, (xmlChar*)"grandson");
    xmlAddChild(node,grandson);
    xmlAddChild(grandson, xmlNewText((xmlChar*)"This is a grandson node"));

    //�洢xml�ĵ�
    int ret = xmlSaveFile(XmlFileName, doc.get());
    if (ret == -1)
    {
        cout << "Create XmlFile failed!" << endl;
        return false;
    }

    return true;
}