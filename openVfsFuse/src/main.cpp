#include <iostream>
#include <fuse.h>

#include "openvfsfuse.h"

int main(int argc, char *argv[])
{
    initializeOpenVFSFuse(argc, argv);
    return 0;
}
