/*  history:
2015-07-06 Created by LiuHao.
*/

#include "SystemInclude.h"
#include "Common.h"
#include "Debug.h"
#include "SystemError.h" 

#include "Rc4.h"
#include "MacHeader.h"
#include "Option.h"
#include "SecurityHeader.h"
#include "PktDbWrapper.h"
#include "PtwLib.h"
#include "Task.h"
#include "Cracker.h"

#include "Main.h"

#ifdef _DEBUG
#define new DEBUG_CLIENTBLOCK
#endif

using namespace std;
using namespace Router;

int main()
{
#if 1
    Cracker cracker;
    cracker.ReadPcapFile("../Packets/aircrack-ng-ptw.cap");
#else
    string str(3, '\0');
    char a = str[3];
#endif

    _CrtMemDumpAllObjectsSince(nullptr);
	return 0;
}
