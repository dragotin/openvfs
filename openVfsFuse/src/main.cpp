#include <iostream>
#include <fuse3/fuse.h>

#include "openvfsfuse.h"

int main(int argc, char *argv[])
{
    initializeOpenVFSFuse(argc, argv);
    return 0;
}
