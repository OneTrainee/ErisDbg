#pragma once
#include <ntifs.h>
union EptCommonEntry {
    ULONG64 all;
    struct {
        ULONG64 read_access : 1;       //!< [0]
        ULONG64 write_access : 1;      //!< [1]
        ULONG64 execute_access : 1;    //!< [2]
        ULONG64 memory_type : 3;       //!< [3:5]
        ULONG64 reserved1 : 6;         //!< [6:11]
        ULONG64 physial_address : 36;  //!< [12:48-1]
        ULONG64 reserved2 : 16;        //!< [48:63]
    } fields;
};
struct EptData;


EptData* EptInitialization();
void EptInitializeMtrrEntries();
void EptHandleEptViolation(EptData* ept_data);
ULONG64 EptGetEptPointer(EptData* ept_data);
void EptTermination(EptData* ept_data);