#include "PluginManager.h"
#include "RemoteServer.h"
#include "MemAccess.h"

#include "remotememaccess.pb.h"

#include <cstring>

extern "C" {
#include <unistd.h>
#include <sys/uio.h>
}

using namespace DFHack;
using namespace dfproto::RemoteMemAccess;

DFHACK_PLUGIN("remotememaccess")

DFhackCExport command_result plugin_init(color_ostream &out, std::vector<PluginCommand> &)
{
    return CR_OK;
}

DFhackCExport command_result plugin_shutdown(color_ostream &out)
{
    return CR_OK;
}

static command_result info(color_ostream &stream, const EmptyMessage *, Info *out)
{
    out->set_version_major(1);
    out->set_version_minor(0);
    out->set_arch(AMD64);
    out->set_os(LINUX);
    out->set_abi(GNU);
    out->set_checksum(Core::getInstance().p->getMD5());
    return CR_OK;
}

static command_result read_raw(color_ostream &stream, const ReadRawIn *in, ReadOut *out)
{
    void *address = reinterpret_cast<void *>(in->address());
    std::size_t length = in->length();
    std::vector<char> data;
    try {
        data.resize(length);
    }
    catch (std::exception &e) {
        stream << "Failed to allocate output buffer: " << e.what() << std::endl;
        return CR_FAILURE;
    }
    auto local = iovec{&data[0], length};
    auto remote = iovec{address, length};
    auto ret = process_vm_readv(getpid(), &local, 1, &remote, 1, 0);
    if (ret == -1) {
        int err = errno;
        stream << "Failed to read memory: " << strerror(err) << std::endl;
        return CR_FAILURE;
    }
    if (ret != length) {
        stream << "Partial read_raw" << std::endl;
    }
    out->mutable_data()->assign(data.begin(), data.end());
    return ret == length ? CR_OK : CR_FAILURE;
}

static command_result read_string(color_ostream &stream, const ReadStringIn *in, ReadOut *out)
{
    stream << "Not implemented" << std::endl;
    return CR_FAILURE;
}

static command_result write_raw(color_ostream &stream, const WriteIn *in)
{
    void *address = reinterpret_cast<void *>(in->address());
    const std::string &data = in->data();
    std::size_t length = data.size();
    auto local = iovec{const_cast<char *>(&data[0]), length};
    auto remote = iovec{address, length};
    auto ret = process_vm_writev(getpid(), &local, 1, &remote, 1, 0);
    if (ret == -1) {
        int err = errno;
        stream << "Failed to write memory: " << strerror(err) << std::endl;
    }
    else if (ret != length) {
        stream << "Partial write_raw" << std::endl;
    }
    return ret == length ? CR_OK : CR_FAILURE;
}

static command_result write_string(color_ostream &stream, const WriteIn *in)
{
    reinterpret_cast<std::string *>(in->address())->assign(in->data());
    return CR_OK;
}

DFhackCExport RPCService *plugin_rpcconnect(color_ostream &)
{
    RPCService *svc = new RPCService();
    svc->addFunction("Info", info);
    svc->addFunction("ReadRaw", read_raw);
    svc->addFunction("ReadString", read_string);
    svc->addFunction("WriteRaw", write_raw);
    svc->addFunction("WriteString", write_string);
    return svc;
}
