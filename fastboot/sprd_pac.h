#include <string>
#include <cstring>

#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>

#include <vector>

#ifdef WIN32
#include <direct.h>
#endif

typedef unsigned long long FILE_SIZE_TYPE;

#if defined(_WIN32)
    #define wchar_t   unsigned short
    #define _TCHAR    wchar_t
    #define TCHAR     wchar_t
    #define DWORD     unsigned long
    #define WORD      unsigned short
    #define PATH_SEP  '\\'
#else
    #define wchar_t   unsigned short
    #define _TCHAR    wchar_t
    #define    TCHAR  wchar_t
    #define DWORD     unsigned int
    #define WORD      unsigned short
    #define PATH_SEP  '/'
#endif

/* Command to flash phone, erasing user data. */
#define FB_CMD_FLASH_PAC    "flash-pac"
/* Command to flash phone, keeping user data. */
#define FB_CMD_FLASH_PACK   "flash-pack"
#define FB_CMD_PARSE_PAC    "parse-pac"
#define MAX_VPAC_SIZE       (512)
#define PAC_MAGIC           (0xFFFAFFFA)
#define MAX_PAC_VER_LEN     (24)

/************************************************************************/
/*  PAC HEADER struct, storing packet header information                */
/************************************************************************/
typedef struct tagPacHeaderBP_R2_0_1 {
    tagPacHeaderBP_R2_0_1() {
        memset(this, 0, sizeof(tagPacHeaderBP_R2_0_1));
        dwMagic = PAC_MAGIC;
    }

    _TCHAR szVersion[22];       // packet struct version; V1->V2 : 24*2 -> 22*2
    DWORD  dwHiSize;            // the whole packet hight size;
    DWORD  dwLoSize;            // the whole packet low size;
    _TCHAR szPrdName[256];      // product name
    _TCHAR szPrdVersion[256];   // product version
    int    nFileCount;          // the number of files that will be downloaded, the file may be an operation
    DWORD  dwFileOffset;        // the offset from the packet file header to the array of FILE_T struct buffer
    DWORD  dwMode;
    DWORD  dwFlashType;
    DWORD  dwNandStrategy;
    DWORD  dwIsNvBackup;
    DWORD  dwNandPageType;
    _TCHAR szPrdAlias[100];     // product alias
    DWORD  dwOmaDmProductFlag;
    DWORD  dwIsOmaDM;
    DWORD  dwIsPreload;
    //Added start
    WORD   wEncrypted;
    WORD   wFTCRC;
    DWORD  dwFTOrgSize;
    DWORD  dwFTEncryptedSize;
    //Added end
    DWORD  dwReserved[197];
    DWORD  dwMagic;
    WORD   wCRC1;
    WORD   wCRC2;
} PacHeaderBP_R2_0_1;

typedef struct _FILE_T {
    _FILE_T() {
        memset(this, 0, sizeof(_FILE_T));
        dwSize = sizeof(_FILE_T);
    }

    DWORD  dwSize;              // size of this struct itself
    _TCHAR szFileID[256];       // file ID,such as FDL,Fdl2,NV and etc.
    _TCHAR szFileName[256];     // file name,in the packet bin file,it only stores file name
                                // but after unpacketing, it stores the full path of bin file
    _TCHAR szFileVersion[252];  // Reserved now; V1->V2 : 256*2 --> 252*2
    DWORD  dwHiFileSize;        // hight file size
    DWORD  dwHiDataOffset;      // hight file offset
    DWORD  dwLoFileSize;        // file size
    int    nFileFlag;           // if "0", means that it need not a file, and
                                // it is only an operation or a list of operations, such as file ID is "FLASH"
                                // if "1", means that it need a file
    DWORD  nCheckFlag;          // if "1", this file must be downloaded;
                                // if "0", this file can not be downloaded;
    DWORD  dwLoDataOffset;      // the offset from the packet file header to this file data
    DWORD  dwCanOmitFlag;       // if "1", this file can not be downloaded and not check it as "All files"
                                // in download and spupgrade tool.
    DWORD  dwAddrNum;
    DWORD  dwAddr[5];
    DWORD  dwReserved[249];     // Reserved for future,not used now
} FILE_T;

typedef struct tagPacImg {
    std::string partition_name;
    std::string img_file_name;

    FILE_SIZE_TYPE dataOffset;
    FILE_SIZE_TYPE fileSize;
} PacImg;

// The following structs are for XML parsing. - Begin.
typedef struct tagNvFlag {
    std::string name;
    std::string check;
} NvFlag;

typedef struct tagBackupFlag {
    std::string use;
    std::vector<NvFlag> nvFlags;
} BackupFlag;

typedef struct tagNvItem {
    std::string name;
    std::string backup;
    std::string id;
    BackupFlag backupFlag;
} NvItem;

typedef struct tagBlock {
    std::string id;
    std::string base;
    std::string size;
} Block;

typedef struct tagFileItem {
    std::string backup;
    std::string CheckCali;
    std::string id;
    std::string idAlias;
    std::string type;
    Block block;
    std::string flag;
    std::string checkFlag;
    std::string description;
    // The following fields are NOT in XML, got from parsed PAC files.
    std::string flashFile;
    FILE_SIZE_TYPE fileSize;
    bool partitionAvailable;
} FileItem;
// The info from XML - End.

typedef struct tagFileTypeInfo {
    const char* ext;
    const char* type;
    int  count;
} FileTypeInfo;

typedef struct tagPartition {
    std::string id;
    std::string size;
} Partition;

typedef enum tagSplloaderStorage {
    NAND = 0x101,
    EMMC = 0x102,
    UFS
} SplloaderStorage;

typedef struct tagPacInfo {
    std::string pacVersion;
    std::string productName;
    std::string productAlias;
    std::string productVersion;

    FILE_SIZE_TYPE pacFileSize;
    int  headerSize;
    int  nFileCount;

    std::vector<PacImg> pacImgList;

    std::string tempDirectory;

    SplloaderStorage splloaderStorage;

    // The following is from XML.
    std::vector<NvItem>     nvItems;
    std::vector<Partition>  partitions;
    std::vector<FileItem>   flashFileItems;
    std::vector<FileItem>   eraseFileItems;
} PacInfo;

const char* PAC_BP_R2_0_1 = "BP_R2.0.1";
const char* PAC_BP_R1_0_0 = "BP_R1.0.0";
const char* partition_splloader = "splloader";
const char* partition_userdata  = "userdata";

const char* SPLLoaderEMMC = "SPLLoaderEMMC";
const char* SPLLoaderUFS  = "SPLLoaderUFS";
const char* SPLLoader = "SPLLoader";

const char* XML = ".xml";
const char* BIN = ".bin";
const char* BMP = ".bmp";
const char* IMG = ".img";
const char* DAT = ".dat";

FileTypeInfo fileTypeInfoArray[] = {
    { BIN, "BIN", 0 },
    { BMP, "BMP", 0 },
    { IMG, "IMG", 0 },
    { DAT, "DAT", 0 },
    { XML, "XML", 0 },
};

const char* PREFIX_ERASE = "Erase";

const char* TAG_FORMAT_PRODUCT_START = "<Product name=\"%s\">"; // %s is product name
const char* TAG_PRODUCT_END = "</Product>";

const char* TAG_FORMAT_SCHEME_START = "<Scheme name=\"%s\">"; // %s is product name
const char* TAG_SCHEME_END = "</Scheme>";
const char* TAG_END_DEFAULT = ">";

const char* TAG_PARTITIONS_START = "<Partitions>";
const char* TAG_PARTITIONS_END   = "</Partitions>";
const char* TAG_PARTITION_START  = "<Partition";
const char* ATTR_SIZE = "size";

const char* TAG_NV_ITEM_START = "<NVItem";
const char* TAG_NV_ITEM_END = "</NVItem>";
const char* TAG_ID_START = "<ID>";
const char* TAG_ID_END = "</ID>";
const char* TAG_BACKUP_FLAG_START = "<BackupFlag";
const char* TAG_BACKUP_FLAG_END = "</BackupFlag>";
const char* TAG_NV_FLAG_START = "<NVFlag";
const char* TAG_NV_FLAG_END = "</NVFlag>";
const char* ATTR_NAME = "name";
const char* ATTR_USE = "use";
const char* ATTR_CHECK = "check";
const char* ATTR_BACKUP = "backup";
const char* ATTR_CHECK_CALI = "CheckCali";
const char* ATTR_ID = "id";

const char* TAG_FILE_ITEM_START = "<File";
const char* TAG_FILE_ITEM_END = "</File>";
const char* TAG_ID_ALIAS_START = "<IDAlias>";
const char* TAG_ID_ALIAS_END = "</IDAlias>";
const char* TAG_TYPE_START = "<Type>";
const char* TAG_TYPE_END = "</Type>";
const char* TAG_BLOCK_START = "<Block";
const char* TAG_BLOCK_END = "</Block>";
const char* TAG_BASE_START = "<Base>";
const char* TAG_BASE_END = "</Base>";
const char* TAG_SIZE_START = "<Size>";
const char* TAG_SIZE_END = "</Size>";
const char* TAG_FLAG_START = "<Flag>";
const char* TAG_FLAG_END = "</Flag>";
const char* TAG_CHECK_FLAG_START = "<CheckFlag>";
const char* TAG_CHECK_FLAG_END = "</CheckFlag>";
const char* TAG_DESCRIPTION_START = "<Description>";
const char* TAG_DESCRIPTION_END = "</Description>";

// Core functions.
static void flashSprdPac(std::vector<std::string> &args, const bool eraseUserData,
                         const std::string& slot_override, const bool force_flash,
                         const bool set_fbe_marker);
static void parse_pac(std::string &pacFilename);
static void readPacInfo(FILE *fp, PacInfo& pacInfo);
static bool readPacHeaderBP_R2_0_1(FILE *fp, PacInfo& pacInfo);
static bool readImgFilesInfo(FILE *fp, PacInfo& pacInfo);
static void writeImgTempFiles(FILE *fp, PacInfo& pacInfo, const bool onlyParse);
static int  loadXmlInfo(PacInfo& pacInfo); // Return the count for the files to be flashed.
static void flashPacImgs(std::string &tempDir, std::vector<FileItem>& flashFileItems,
                         const std::string& slot_override, const bool force_flash,
                         const bool eraseUserData);
static void erasePartitions(std::vector<FileItem>& eraseFileItems, const std::string& slot_override);
static void wipeUserData(const bool set_fbe_marker);
static SplloaderStorage getSplloaderStorageByProduct(std::string &productName);

// Accessory functions.
static bool isFusedDevice();
static std::string getProductName();
static std::string getTempFilePath(std::string dirPath, std::string filename);
static void showPacInfo(PacInfo &pacInfo);
static std::string getField(char* data, const char* tagStart, const char* tagEnd);
static std::string getAttr(char* data, const char* tagStart, const char* attr);
static Block getFileBlockInfo(char* data);
static void fillBackupFlagNvFlags(char *data, std::vector<NvFlag> &nvFlags);
static BackupFlag getBackupFlag(char* data);

// Utility functions.
static std::string tcharsString(_TCHAR* tchars, const int count);
static bool endsWith(const std::string& s, const char* suffix);
static bool startsWith(const std::string& s, const char* prefix);
static bool _mkdir(const char* dirPath, const bool cleanDir);

static bool isPartitionForUserData(std::string& partition) {
    if (partition == "userdata") return true;
    if (partition == "metadata") return true;
    return false;
}

static bool isPartitionSkipped(std::string& partition) {
    if (partition == "factory") return true;
    if (partition == "miscdata") return true;
    if (partition == "prodnv") return true;
    if (partition == "persist") return true;
    return false;
}

static void removeUserDataPartitionsFromEraseItems(std::vector<FileItem> &eraseFileItems) {
    eraseFileItems.erase(std::remove_if(eraseFileItems.begin(), eraseFileItems.end(),
                   [](FileItem& fileItem) -> bool {
                         if (isPartitionForUserData(fileItem.block.id)) {
                             fprintf(stdout, "\n ** Remove partition '%s' from erase items.", fileItem.id.c_str());
                             return true;
                         }
                         return false;
                   }), eraseFileItems.end());
}

static bool isCompatibleProduct(std::string &pacProduct, const std::string &curProduct) {
    if (pacProduct == curProduct) return true;
    const char *pac_product = pacProduct.c_str();
    const char *cur_product = curProduct.c_str();
    if (strcmp(pac_product, "ums9230_aruba_go") == 0) {
         return strcmp(cur_product, "aruba") == 0;
    }
    if (strcmp(pac_product, "ums512_1h10") == 0) {
        return strcmp(cur_product, "cyprus_64") == 0;
    }
    if (strcmp(pac_product, "ums512_1h10_go") == 0) {
        return strcmp(cur_product, "cyprus_32") == 0;
    }
    return false;
}

static bool readPacToImgs(const std::string& pacFilename, PacInfo& pacInfo,
                          const std::string& productName = "") {
    const bool onlyParse = productName.empty();
    FILE *fp = fopen(pacFilename.c_str(), "rb");
    bool done = false;
    if (!fp) {
        fprintf(stderr, "\n ** Failed to open PAC file!\n -> %s", pacFilename.c_str());
        goto READ_ERROR;
    }
#if defined(_WIN32)
    {
        _fseeki64(fp, 0, SEEK_END);
        pacInfo.pacFileSize = _ftelli64(fp);
        _fseeki64(fp, 0, 0);
    }
#else
    {
        fseek(fp, 0, SEEK_END);
        pacInfo.pacFileSize = ftell(fp);
        fseek(fp, 0, 0);
    }
#endif
    if (pacInfo.pacFileSize <= 0) {
        fprintf(stderr, "\n ** Failed to get PAC file size!!\n-> '%s'\n", pacFilename.c_str());
        goto READ_ERROR;
    }
    readPacInfo(fp, pacInfo);
    if (pacInfo.pacVersion.length() <= 0) {
        fprintf(stderr, "\n ** Unknown PAC file!! Empty version info!\n-> '%s'\n", pacFilename.c_str());
        goto READ_ERROR;
    }
    showPacInfo(pacInfo);
    if (pacInfo.productName.empty()) {
        fprintf(stderr, "\n ** Empty product name in pac file?!\n->'%s'", pacFilename.c_str());
        goto READ_ERROR;
    }
    if (!onlyParse && !isCompatibleProduct(pacInfo.productName, productName)) {
        fprintf(stderr, "\n ** Not the same product!\n  - Pac product: %s, Current product: %s\n",
                pacInfo.productName.c_str(), productName.c_str());
        goto READ_ERROR;
    }
    if (readImgFilesInfo(fp, pacInfo)) {
        writeImgTempFiles(fp, pacInfo, onlyParse);
        done = true;
    }
READ_ERROR:
    if (fp) {
        fclose(fp);
        fp = NULL;
    }
    return done;
}

static FILE_SIZE_TYPE FillSize(const DWORD loValue, const DWORD hiValue) {
    FILE_SIZE_TYPE value = hiValue;
    return (value << 32) + loValue; // 32: 4 bytes is 32 bits
}

static bool readImgFilesInfo(FILE *fp, PacInfo& pacInfo) {
    int ignored = 0;
#if defined(_WIN32)
    _fseeki64(fp, pacInfo.headerSize, SEEK_SET);
#else
    fseek(fp, pacInfo.headerSize, SEEK_SET);
#endif
    FILE_SIZE_TYPE expectedSize = pacInfo.headerSize + pacInfo.nFileCount * sizeof(FILE_T);
    for (int fileIndex = 0; fileIndex < pacInfo.nFileCount; fileIndex++) {
        FILE_T fileStruct;
        memset(&fileStruct, 0, sizeof(FILE_T));
        if (fread(&fileStruct, sizeof(FILE_T), 1, fp) != 1) {
            fprintf(stderr, "\nFailed to read PAC file info %d !\nError: %s\n", fileIndex + 1,
                    strerror(errno));
            return false;
        }
        std::string partition = tcharsString(fileStruct.szFileID, 256);
        std::string filename = tcharsString(fileStruct.szFileName, 256);
        if (fileStruct.dwHiFileSize <= 0 && fileStruct.dwLoDataOffset <= 0) {
            ignored++;
            continue;
        }
        PacImg pacImg;
        pacImg.partition_name = partition;
        pacImg.img_file_name = filename;
        pacImg.dataOffset = FillSize(fileStruct.dwLoDataOffset, fileStruct.dwHiDataOffset);
        pacImg.fileSize = FillSize(fileStruct.dwLoFileSize, fileStruct.dwHiFileSize);
        pacInfo.pacImgList.push_back(pacImg);
        expectedSize += pacImg.fileSize;
        if (feof(fp)) {
            fprintf(stderr, "\nFailed to read file info %d!\nError: Unexpected EOF!\n", fileIndex + 1);
            break;
        }
    }
    if (expectedSize != pacInfo.pacFileSize) {
        fprintf(stderr, "\nExpected Size: %llu bytes\nPAC file size: %llu bytes\nPlease check why not same!!",
                expectedSize, pacInfo.pacFileSize);
        return false;
    }
    fprintf(stdout, "\n - Totally %d files in SPRD PAC. %d files ignored for size 0.",
            pacInfo.nFileCount, ignored);
    return true;
}

static bool writeFile(FILE *fp, std::string outputFilepath, const FILE_SIZE_TYPE offset,
                      const FILE_SIZE_TYPE size) {
    const char* filename = outputFilepath.c_str();
    const unsigned long K = 1024L;
    const unsigned long M = 1024L * K;
    const unsigned long BLOCK_SIZE = 2 * M; // 2 Megabytes.
    void *data = malloc(BLOCK_SIZE);
    if (!data) {
        fprintf(stderr, "\nFailed to allocate memory to write temp file!\n%s\n", filename);
        return false;
    }
    FILE *os = fopen(filename, "wb");
    if (!os) {
        fprintf(stderr, "\nFailed to write to temp file:\n%s\n", filename);
        return false;
    }
    bool done = true;
    FILE_SIZE_TYPE curWritten = 0;
    do {
#if defined(_WIN32)
        _fseeki64(fp, 0, offset + curWritten);
#else
        fseek(fp, 0, offset + curWritten);
#endif
        FILE_SIZE_TYPE toRead = size - curWritten;
        if (toRead > BLOCK_SIZE) toRead = BLOCK_SIZE;
        if (fread(data, toRead, 1, fp) == 1) {
            fwrite(data, toRead, 1, os);
            curWritten += toRead;
        } else {
            done = false;
            break;
        }
    } while (size - curWritten > 0);
    fclose(os);
    os = NULL;
    return done;
}

static const char* checkFileType(std::string filename) {
    for (auto& fileTypeInfo : fileTypeInfoArray) {
        if (endsWith(filename, fileTypeInfo.ext)) {
            fileTypeInfo.count++;
            return fileTypeInfo.ext;
        }
    }
    return NULL;
}

static void showFileTypeInfo() {
    char countInfo[256] = {0};
    for (auto& fti : fileTypeInfoArray) {
        int curLen = strlen(countInfo);
        if (curLen > 0) snprintf(countInfo + curLen, 3, ", ");
        snprintf(countInfo + strlen(countInfo), 10, "%s: %d", fti.type, fti.count);
    }
    fprintf(stdout, " - (%s)\n", countInfo);
}

static void writeImgTempFiles(FILE *fp, PacInfo& pacInfo, const bool onlyParse) {
    if (!_mkdir(pacInfo.tempDirectory.c_str(), true)) return;
    for (auto &fileTypeInfo : fileTypeInfoArray) fileTypeInfo.count = 0;
    const int count = pacInfo.pacImgList.size();
    if (onlyParse) {
        fprintf(stdout, "\n - Parsing %d files(except XML) into folder '%s'...", count,
                pacInfo.tempDirectory.c_str());
    }
    int curIndex = 0;
    for (const auto& pacImg : pacInfo.pacImgList) {
        curIndex++;
        const char* extType = checkFileType(pacImg.img_file_name);

        std::string curTempFile;
        if (extType == XML) {
            curTempFile = pacImg.img_file_name;
        } else {
            curTempFile = getTempFilePath(pacInfo.tempDirectory, pacImg.img_file_name);
        }

        if (extType == NULL) {
            fprintf(stdout, "\n  -- [%02d/%d] Unknown file?! -[%s] (%llu bytes)", curIndex, count,
                    pacImg.img_file_name.c_str(), pacImg.fileSize);
        }
        if (onlyParse) {
            fprintf(stdout, "\n  -- [%02d/%d](%-20s) %s (%llu bytes)", curIndex, count,
                    pacImg.partition_name.c_str(),   pacImg.img_file_name.c_str(), pacImg.fileSize);
            if (extType == XML) fprintf(stdout, " *--* in the current folder!");
        }
        if (!writeFile(fp, curTempFile, pacImg.dataOffset, pacImg.fileSize)) {
            fprintf(stderr, "\n[%02d/%d] Failed to create temp file for %s (%llu bytes)", curIndex,
                    count, pacImg.img_file_name.c_str(), pacImg.fileSize);
        }
    }
    fprintf(stdout, "\n - %d files parsed", count);
    showFileTypeInfo();
}

static void readPacInfo(FILE *fp, PacInfo& pacInfo) {
    _TCHAR szVersion[MAX_PAC_VER_LEN];
#if defined(_WIN32)
    _fseeki64(fp, 0, 0);
#else
    fseek(fp, 0, 0);
#endif
    if (fread(szVersion, sizeof(szVersion), 1, fp) == 1) {
        std::string pacVersion = tcharsString(szVersion, MAX_PAC_VER_LEN);
        const char *pac_version = pacVersion.c_str();
        if (strcmp(PAC_BP_R2_0_1, pac_version) == 0) {
            readPacHeaderBP_R2_0_1(fp, pacInfo);
            return;
        }
        if (strcmp(PAC_BP_R1_0_0, pac_version) == 0) {
            // SPRD confirmed that 2.0.1 is compatible with 1.0.0
            readPacHeaderBP_R2_0_1(fp, pacInfo);
            return;
        }
        fprintf(stderr, "\nNew PAC format - %s?!", pac_version);
    }
}

static SplloaderStorage getSplloaderStorageByProduct(std::string &productName) {
    const char* product = productName.c_str();
    if (strcmp(product, "aruba") == 0) return EMMC;
    if (strcmp(product, "ums9230_aruba_go") == 0) return EMMC;
    return NAND;
}

static bool readPacHeaderBP_R2_0_1(FILE *fp, PacInfo& pacInfo) {
    const int headerSize = sizeof(PacHeaderBP_R2_0_1);
#if defined(_WIN32)
    _fseeki64(fp, 0, 0);
#else
    fseek(fp, 0, 0);
#endif
    PacHeaderBP_R2_0_1 pacHeader;
    if (fread(&pacHeader, headerSize, 1, fp) == 1) {
        pacInfo.pacVersion     = tcharsString(pacHeader.szVersion,     22);
        pacInfo.productName    = tcharsString(pacHeader.szPrdName,    256);
        pacInfo.productVersion = tcharsString(pacHeader.szPrdVersion, 256);
        pacInfo.productAlias   = tcharsString(pacHeader.szPrdAlias,   100);
        pacInfo.headerSize     = headerSize;
        pacInfo.nFileCount     = pacHeader.nFileCount;
        if (pacInfo.productName.empty()) {
            fprintf(stderr, "\nFailed to read product name from PacHeader BP_R2_0_1 !");
            return false;
        }
        return true;
    }
    fprintf(stderr, "\nFailed to read PacHeader BP_R2_0_1 !\nError: %s", strerror(errno));
    return false;
}

// Info functions.
static void showPacInfo(PacInfo &pacInfo) {
    std::string stars(67, '*');
    const char* pstars = stars.c_str();
    fprintf(stdout, "\n%10s%s", " ", pstars);
    fprintf(stdout, "\n%10s* UniSoc PAC version: %-43s *", " ", pacInfo.pacVersion.c_str());
    fprintf(stdout, "\n%10s*       Product Name: %-43s *", " ", pacInfo.productName.c_str());
    if (pacInfo.productName.compare(pacInfo.productAlias)) {
        fprintf(stdout, "\n%10s*      Product Alias: %-43s *", " ", pacInfo.productAlias.c_str());
    }
    fprintf(stdout, "\n%10s*    Product Version: %-43s *", " ", pacInfo.productVersion.c_str());
    fprintf(stdout, "\n%10s%s\n", " ", pstars);
}

static void showDone() {
    const int countStar = 67;
    std::string stars(countStar, '*');
    const char* pstars = stars.c_str(); // 47 '*' in a line.
    const char* done = "Flashing SPRD PAC done!!!";
    const int countSpace = (countStar - strlen(done) - 2) >> 1;
    std::string spaces(countSpace, ' '); // spaces before and after done prompt.
    const char* pspaces = spaces.c_str();
    fprintf(stdout, "\n%10s%s",       " ", pstars);
    fprintf(stdout, "\n%10s*%s%s%s*", " ", pspaces, done, pspaces);
    fprintf(stdout, "\n%10s%s\n",     " ", pstars);
}

// Accessory functions.
static void findFileForItem(std::vector<PacImg>& pacImgList, FileItem &fileItem) {
    for (const auto& pacImg : pacImgList) {
        if (pacImg.partition_name == fileItem.id) {
            fileItem.flashFile = pacImg.img_file_name;
            fileItem.fileSize = pacImg.fileSize;
            return;
        }
    }
}

static void readNvItems(char* data, const char* productName, std::vector<NvItem> &nvItems) {
    char tagProductName[256] = {0};
    snprintf(tagProductName, strlen(TAG_FORMAT_PRODUCT_START) - 2 + strlen(productName) + 1,
             TAG_FORMAT_PRODUCT_START, productName);
    //fprintf(stdout, "\ntagProductName: %s", tagProductName);
    char* start = strstr(data, tagProductName);
    if (start == NULL) return;
    start += strlen(tagProductName);
    char* end = strstr(data, TAG_PRODUCT_END);
    if (end == NULL || end <= start) return;
    char* curPos = start;
    while (curPos < end) {
        char *itemStart = strstr(curPos, TAG_NV_ITEM_START);
        if (itemStart == NULL) break;
        char *itemEnd = strstr(curPos, TAG_NV_ITEM_END);
        if (itemEnd == NULL || itemEnd <= itemStart) break;
        curPos = itemEnd + strlen(TAG_NV_ITEM_END);

        char* itemData = (char*)malloc(itemEnd - itemStart + 1);
        memset(itemData, 0, itemEnd - itemStart + 1);
        strncpy(itemData, itemStart, itemEnd - itemStart);
        NvItem nvItem;
        nvItem.id = getField(itemData, TAG_ID_START, TAG_ID_END);
        nvItem.name = getAttr(itemData, TAG_NV_ITEM_START, ATTR_NAME);
        nvItem.backup = getAttr(itemData, TAG_NV_ITEM_START, ATTR_BACKUP);
        nvItem.backupFlag = getBackupFlag(itemData);
        nvItems.push_back(nvItem);
        free(itemData);
    }
}

static void readPartitions(char* data, std::vector<Partition> &partitions) {
    char* start = strstr(data, TAG_PARTITIONS_START);
    if (start == NULL) return;
    start += strlen(TAG_PARTITIONS_START);
    char* end = strstr(start, TAG_PARTITIONS_END);
    if (end == NULL || end <= start) return;
    char* curPos = start;
    while (curPos < end) {
        char *itemStart = strstr(curPos, TAG_PARTITION_START);
        if (itemStart == NULL) break;
        char *itemEnd = strstr(itemStart, TAG_END_DEFAULT);
        if (itemEnd == NULL || itemEnd <= itemStart) break;
        curPos = itemEnd + strlen(TAG_END_DEFAULT);

        char* itemData = (char*)malloc(itemEnd - itemStart + 1);
        strncpy(itemData, itemStart, itemEnd - itemStart);
        Partition partition;
        partition.id   = getAttr(itemData, TAG_PARTITION_START, ATTR_ID);
        partition.size = getAttr(itemData, TAG_PARTITION_START, ATTR_SIZE);
        partitions.push_back(partition);
        free(itemData);
    }
}

static bool isExpectedPartition(FileItem &fileItem, PacInfo &pacInfo) {
    const char * partition = fileItem.block.id.c_str();
    if (strlen(partition) <= 0) return true;
    const char * id = fileItem.id.c_str();
    if (strcmp(partition, partition_splloader) == 0) {
        switch (pacInfo.splloaderStorage) {
            case EMMC:
                return strcmp(id, SPLLoaderEMMC) == 0;
            case UFS:
                return strcmp(id, SPLLoaderUFS) == 0;
            default:
                return strcmp(id, SPLLoader) == 0;
        }
        return true;
    }
    return true;
}

static int findFileItem(std::vector<FileItem> &fileItems, std::string &partitionName) {
    if (partitionName.empty()) return -1;
    if (fileItems.size() <= 0) return -1;
    const char* partition = partitionName.c_str();
    int index = -1;
    for (auto& fileItem : fileItems) {
        index++;
        if (fileItem.block.id.empty()) continue;
        const char* cur_partition = fileItem.block.id.c_str();
        if (strcmp(partition, cur_partition) == 0) return index;
    }
    return -1;
}

static void checkFileItems(PacInfo &pacInfo) {
    // If the flash file item exists in erase file items,
    // remove it from erase file items.
    for (auto& flashItem : pacInfo.flashFileItems) {
        int position = findFileItem(pacInfo.eraseFileItems, flashItem.block.id);
        if (position < 0) continue;
        FileItem & foundItem = pacInfo.eraseFileItems[position];
        pacInfo.eraseFileItems.erase(pacInfo.eraseFileItems.begin() + position);
        fprintf(stdout, "\n -*- Ignored erasing partition '%s', to be flashed.",
                foundItem.block.id.c_str());
        if (pacInfo.eraseFileItems.size() <= 0) break;
    }
}

static void readFileItems(char* data, const char* productName, PacInfo &pacInfo) {
    char tagSchemeName[256] = {0};
    snprintf(tagSchemeName, strlen(TAG_FORMAT_SCHEME_START) - 2 + strlen(productName) + 1,
             TAG_FORMAT_SCHEME_START, productName);
    //fprintf(stdout, "\ntagSchemeName: %s", tagSchemeName);
    char* start = strstr(data, tagSchemeName);
    if (start == NULL) return;
    start += strlen(tagSchemeName);
    char *end = strstr(data, TAG_SCHEME_END);
    if (end == NULL || end <= start) return;
    char* curPos = start;
    while (curPos < end) {
        char *itemStart = strstr(curPos, TAG_FILE_ITEM_START);
        if (itemStart == NULL) break;
        char *itemEnd = strstr(curPos, TAG_FILE_ITEM_END);
        if (itemEnd == NULL || itemEnd <= itemStart) break;
        curPos = itemEnd + strlen(TAG_FILE_ITEM_END);

        char* itemData = (char*)malloc(itemEnd - itemStart + 1);
        memset(itemData, 0, itemEnd - itemStart + 1);
        strncpy(itemData, itemStart, itemEnd - itemStart);
        FileItem fileItem;
        fileItem.backup = getAttr(itemData, TAG_FILE_ITEM_START, ATTR_BACKUP);
        fileItem.CheckCali = getAttr(itemData, TAG_FILE_ITEM_START, ATTR_CHECK_CALI);
        fileItem.id = getField(itemData, TAG_ID_START, TAG_ID_END);
        fileItem.idAlias = getField(itemData, TAG_ID_ALIAS_START, TAG_ID_ALIAS_END);
        fileItem.type = getField(itemData, TAG_TYPE_START, TAG_TYPE_END);
        fileItem.block = getFileBlockInfo(itemData);
        fileItem.flag = getField(itemData, TAG_FLAG_START, TAG_FLAG_END);
        fileItem.checkFlag = getField(itemData, TAG_CHECK_FLAG_START, TAG_CHECK_FLAG_END);
        fileItem.description = getField(itemData, TAG_DESCRIPTION_START, TAG_DESCRIPTION_END);
        if (startsWith(fileItem.type, PREFIX_ERASE)) {
            pacInfo.eraseFileItems.push_back(fileItem);
        } else if (isExpectedPartition(fileItem, pacInfo)) {
            pacInfo.flashFileItems.push_back(fileItem);
        }
        free(itemData);
    }
    if (pacInfo.eraseFileItems.size() > 0 && pacInfo.flashFileItems.size() > 0) {
        checkFileItems(pacInfo);
    }
}

static void parseXml(std::string xml_file, const FILE_SIZE_TYPE sizeBytes, PacInfo &pacInfo) {
    char* data = (char*)malloc(sizeBytes + 1);
    if (!data) return;
    memset(data, 0, sizeBytes + 1);
    FILE *fp = fopen(xml_file.c_str(), "rb");
    int read = -1;
    if (fp) {
        read = fread(data, sizeBytes, 1, fp);
        fclose(fp);
    }
    const char* product_name = pacInfo.productName.c_str();
    if (read != 1) goto RET;
    readNvItems(data, product_name, pacInfo.nvItems);
    readPartitions(data, pacInfo.partitions);
    readFileItems(data, product_name, pacInfo);
RET:
    free(data);
    data = NULL;
}

static bool partitionListed(std::vector<Partition>& partitions, const char* inputPartition) {
    if (!inputPartition || strlen(inputPartition) <= 0) return false;
    for (auto& partition : partitions) {
        if (strcmp(partition.id.c_str(), inputPartition) == 0) return true;
    }
    if (strcmp(inputPartition, partition_splloader) == 0) return true;
    return false;
}

static int loadXmlInfo(PacInfo& pacInfo) {
    for (const auto& pacImg : pacInfo.pacImgList) {
        if (!endsWith(pacImg.img_file_name, XML)) continue;
        fprintf(stdout, "\n --- loading XML ... %s, %llu bytes", pacImg.img_file_name.c_str(),
                pacImg.fileSize);
        parseXml(pacImg.img_file_name, pacImg.fileSize, pacInfo);
    }
    int flashCount = 0, noFileCount = 0, noPartitionIdCount = 0, notPartitionCount = 0;
    for (auto& fileItem : pacInfo.flashFileItems) {
        findFileForItem(pacInfo.pacImgList, fileItem);
        fileItem.partitionAvailable = false;
        if (fileItem.flashFile.length() <= 0) {
            noFileCount++;
            continue;
        }
        if (fileItem.block.id.length() <= 0) {
            noPartitionIdCount++;
            continue;
        }
        if (!partitionListed(pacInfo.partitions, fileItem.block.id.c_str())) {
            notPartitionCount++;
            continue;
        }
        fileItem.partitionAvailable = true;
        flashCount++;
    }
    const int nvItemCount = pacInfo.nvItems.size();
    fprintf(stdout, "\n   -- %-3d   NV items", nvItemCount);
    const int partitionCount = pacInfo.partitions.size();
    fprintf(stdout, "\n   -- %-3d partitions", partitionCount);
    const int fileItemCount = pacInfo.flashFileItems.size();
    fprintf(stdout, "\n   -- %-3d file items - %d files available for flashing (no file: %d,"
            " no partition id: %d, not listed partition: %d)",
            fileItemCount, flashCount, noFileCount, noPartitionIdCount, notPartitionCount);
    return flashCount;
}

static std::string getTempFilePath(std::string dirPath, std::string filename) {
    return dirPath + PATH_SEP + filename;
}

static std::string getFilename(std::string filepath) {
    std::string filename = filepath;
    const size_t last_slash_idx = filename.find_last_of("\\/");
    if (std::string::npos != last_slash_idx) {
        filename.erase(0, last_slash_idx + 1);
    }
    // Remove extension if present.
    const size_t period_idx = filename.rfind('.');
    if (std::string::npos != period_idx) {
        filename.erase(period_idx);
    }
    return filename;
}

// Utility functions.
static std::string tcharsString(_TCHAR* tchars, const int count) {
    std::string s;
    for (int i = 0; i < count; i++) {
        char ch = tchars[i];
        if (ch == '\0') break;
        s += ch;
    }
    return s;
}

static bool endsWith(const std::string& s, const char* suffix) {
    const int suffixLen = strlen(suffix);
    const int inputLen = s.length();
    if (suffixLen > inputLen) return false;
    for (int i = 0; i < suffixLen; i++) {
        if (s[inputLen - i - 1] != suffix[suffixLen - i - 1]) return false;
    }
    return true;
}

static bool startsWith(const std::string& s, const char* prefix) {
    const int prefixLen = strlen(prefix);
    const int inputLen = s.length();
    if (prefixLen > inputLen) return false;
    for (int i = 0; i < prefixLen; i++) {
        if (s[i] != prefix[i]) return false;
    }
    return true;
}

static std::string getField(char* data, const char* tagStart, const char* tagEnd) {
    std::string emptyField;
    char* start = strstr(data, tagStart);
    if (start == NULL) return emptyField;
    start += strlen(tagStart);
    char* end = strstr(start, tagEnd);
    if (end == NULL || end <= start) return emptyField;
    while (*start == ' ' || *start == '\n') start++;
    while (*(end - 1) == ' ' || *(end - 1) == '\n') end--;
    std::string field(start, end - start);
    return field;
}

static std::string getAttr(char* data, const char* tagStart, const char* attr) {
    char attrStart[128] = {0};
    snprintf(attrStart, 128, "%s=\"", attr);
    char* start = strstr(data, tagStart);
    std::string emptyValue;
    if (start == NULL) return emptyValue;
    start = strstr(start, attrStart);
    if (start == NULL) return emptyValue;
    start += strlen(attrStart);
    const char* attrEndTag = "\"";
    char* end = strstr(start, attrEndTag);
    if (end == NULL || end <= start) return emptyValue;
    std::string value(start, end - start);
    return value;
}

static Block getFileBlockInfo(char* data) {
    Block block;
    char* start = strstr(data, TAG_BLOCK_START);
    if (start == NULL) return block;
    char* end = strstr(data, TAG_BLOCK_END);
    if (end == NULL || end <= start) return block;
    block.id = getAttr(data, TAG_BLOCK_START, ATTR_ID);
    block.base = getField(start, TAG_BASE_START, TAG_BASE_END);
    block.size = getField(start, TAG_SIZE_START, TAG_SIZE_END);
    return block;
}

static void fillBackupFlagNvFlags(char *data, std::vector<NvFlag> &nvFlags) {
    char* curPos = data;
    while (true) {
        char *flagStart = strstr(curPos, TAG_NV_FLAG_START);
        if (flagStart == NULL) break;
        char *flagEnd = strstr(curPos, TAG_NV_FLAG_END);
        if (flagEnd == NULL || flagEnd <= flagStart) break;
        curPos = flagEnd + strlen(TAG_NV_FLAG_END);

        char* flagData = (char*)malloc(flagEnd - flagStart + 1);
        memset(flagData, 0, flagEnd - flagStart + 1);
        strncpy(flagData, flagStart, flagEnd - flagStart);
        NvFlag nvFlag;
        nvFlag.name = getAttr(flagData, TAG_NV_FLAG_START, ATTR_NAME);
        nvFlag.check = getAttr(flagData, TAG_NV_FLAG_START, ATTR_CHECK);
        nvFlags.push_back(nvFlag);
        free(flagData);
    }
}

static BackupFlag getBackupFlag(char* data) {
    BackupFlag backupFlag;
    char* start = strstr(data, TAG_BACKUP_FLAG_START);
    if (start == NULL) return backupFlag;
    char* end = strstr(data, TAG_BACKUP_FLAG_END);
    if (end == NULL || end <= start) return backupFlag;
    backupFlag.use = getAttr(data, TAG_BACKUP_FLAG_START, ATTR_USE);
    fillBackupFlagNvFlags(data, backupFlag.nvFlags);
    return backupFlag;
}

static bool dirExists(const char *path) {
    struct stat info;
    if (stat(path, &info ) == 0) {
        if (info.st_mode & S_IFDIR) return true;
    }
    return false;
}

#ifdef WIN32
static bool isDir(const char *path) {
    struct stat statbuf;
    if (stat(path, &statbuf) != 0) {
        return false;
    }
    return S_ISDIR(statbuf.st_mode);
}
#endif

static inline void deleteRecursive(const char* path) {
    std::string pathStr(path);
    if (pathStr[pathStr.size()-1] != PATH_SEP) {
        pathStr += PATH_SEP;
    }

    DIR* dir = opendir(path);
    if (!dir) {
        fprintf(stderr, "Failed to opendir: %s", path);
        return;
    }

    struct dirent* entry;
    while ((entry = readdir(dir))) {
        const char* name = entry->d_name;

        // ignore "." and ".."
        if (name[0] == '.' && (name[1] == 0 || (name[1] == '.' && name[2] == 0))) {
            continue;
        }
        std::string child_path = pathStr + name;
        const char* childPath = child_path.c_str();

        int success;
#ifdef WIN32
        if (isDir(childPath)) {
#else
        if (entry->d_type == DT_DIR) {
#endif
            deleteRecursive(childPath);
            success = rmdir(childPath);
        } else {
            success = unlink(childPath);
        }
        if (success == -1) {
            fprintf(stderr, "Failed to delete child %s", childPath);
        }
    }
    closedir(dir);
}

static bool deletePath(const char *path) {
    struct stat statbuf;
    if (stat(path, &statbuf) != 0) {
        return false;
    }
    int success;
    if (S_ISDIR(statbuf.st_mode)) {
#ifdef WIN32
        char cmd_rd[64] = { 0 };
        snprintf(cmd_rd, 64, "rmdir /Q/S \"%s\"", path);
        success = system(cmd_rd);
#else
        // rmdir will fail if the directory is non empty,
        // so there is no need to keep errors from deleteRecursive.
        deleteRecursive(path);
        success = rmdir(path);
#endif
    } else {
#ifdef WIN32
        char cmd_del[64] = { 0 };
        snprintf(cmd_del, 64, "del /F/Q \"%s\"", path);
        success = system(cmd_del);
#else
        success = unlink(path);
#endif
    }
    return success == 0;
}

static bool _mkdir(const char* dirPath, const bool cleanDir) {
    if (!dirPath || strlen(dirPath) <= 0) {
        fprintf(stderr, "\n ** Failed to create the temp directory!\nError: EMPTY temp DIR!\n");
        return false;
    }
    if (dirExists(dirPath)) {
        //fprintf(stdout, "\n ** temp directory exists!\n");
        if (!cleanDir) return true;
        if (!deletePath(dirPath)) {
            fprintf(stderr, "\n ** Failed to remove the existing temp directory!\nError: %s!\n",
                    strerror(errno));
            return false;
        }
    }
#ifdef WIN32
    const int dir_err = mkdir(dirPath);
#else
    const int dir_err = mkdir(dirPath, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
#endif
    if (-1 == dir_err) {
        fprintf(stderr, "\n ** Failed to create the temp directory!\n -> %s\nError: %s\n", dirPath,
                strerror(errno));
        return false;
    }
    return true;
}

