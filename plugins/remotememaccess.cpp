#include "PluginManager.h"
#include "RemoteServer.h"
#include "MemAccess.h"

#include "remotememaccess.pb.h"

extern "C" {
#include <string.h>
#include <signal.h>
#include <setjmp.h>
}

using namespace DFHack;
using namespace dfproto::RemoteMemAccess;

DFHACK_PLUGIN("remotememaccess")

struct Copy {
    const char *in;
    char *out;
    std::size_t size;
    bool operator() () {
        std::copy_n(in, size, out);
        return true;
    }
};

struct CheckString
{
    const void *addr;
    std::size_t len;
    bool operator() () {
        struct Rep {
            std::size_t length;
            std::size_t capacity;
            int refcount;
        };
        const Rep *rep = *reinterpret_cast<const Rep * const *>(addr);
        --rep;
        if (rep->length > rep->capacity) {
            return false;
        }
        len = rep->length;
        return true;
    }
};

static jmp_buf segv_caught;

static void segv_handler(int signum)
{
    longjmp(segv_caught, 1);
}

template<typename Func>
bool segv_safe(color_ostream &stream, Func &&f)
{
    int error;
    bool success;

    struct sigaction new_sa, old_sa;
    memset(&new_sa, 0, sizeof(struct sigaction));
    new_sa.sa_handler = segv_handler;

    sigset_t sigmask;
    if (-1 == sigprocmask(SIG_SETMASK, NULL, &sigmask)) {
        error = errno;
        stream << "Failed to save signal mask: " << strerror(error) << std::endl;
        return false;
    }
    if (setjmp(segv_caught) == 0) {
        if (-1 == sigaction(SIGSEGV, &new_sa, &old_sa)) {
            error = errno;
            stream << "Failed to change signal hander: " << strerror(error) << std::endl;
            return false;
        }
        success = f();
    }
    else { // a segfault happened during the copy
        // the signal mask is still the one from the signal handler, we need to restore it.
        if (-1 == sigprocmask(SIG_SETMASK, &sigmask, NULL)) {
            error = errno;
            stream << "Failed to restore signal mask: " << strerror(error) << std::endl;
        }
        success = false;
    }
    if (-1 == sigaction(SIGSEGV, &old_sa, NULL)) {
        error = errno;
        stream << "Failed to restore signal handler: " << strerror(error) << std::endl;
    }
    return success;
}

static bool safe_copy(color_ostream &stream, const char *in, std::size_t size, char *out)
{
    return segv_safe(stream, Copy { in, out, size });
}

static bool safe_read_string(color_ostream &stream, const void *addr, std::string &out)
{
    CheckString check_string { addr };
    if (!segv_safe(stream, check_string)) {
        stream << "Address do not point to a valid string" << std::endl;
        return false;
    }

    try {
        out.resize(check_string.len);
    }
    catch (std::exception &e) {
        stream << "Failed to allocate string buffer: " << e.what() << std::endl;
        return false;
    }

    const std::string *str = reinterpret_cast<const std::string *>(addr);
    return segv_safe(stream, Copy { str->data(), &out[0], check_string.len });
}

static bool safe_write_string(color_ostream &stream, void *addr, const std::string &data)
{
    CheckString check_string { addr };
    if (!segv_safe(stream, check_string)) {
        stream << "Address do not point to a valid string" << std::endl;
        return false;
    }

    std::string *str = reinterpret_cast<std::string *>(addr);
    try {
        // TODO: Require segv_safe block? Is lonjmp from std::string::assign ok?
        str->assign(data);
    }
    catch (std::exception &e) {
        stream << "Failed to assign string: " << e.what() << std::endl;
        return false;
    }
    return true;
}


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
    std::string *data = out->mutable_data();
    try {
        data->resize(in->length());
    }
    catch (std::exception &e) {
        stream << "Failed to allocate output buffer: " << e.what() << std::endl;
        return CR_FAILURE;
    }
    if (!safe_copy(stream, reinterpret_cast<const char *>(in->address()), in->length(), &(*data)[0])) {
        stream << "Failed to read raw data." << std::endl;
        return CR_FAILURE;
    }
    return CR_OK;
}

static command_result read_string(color_ostream &stream, const ReadStringIn *in, ReadOut *out)
{
    if (!safe_read_string(stream, reinterpret_cast<const void *>(in->address()), *out->mutable_data())) {
        stream << "Failed to read string." << std::endl;
        return CR_FAILURE;
    }
    return CR_OK;
}

static command_result write_raw(color_ostream &stream, const WriteIn *in)
{
    if (!safe_copy(stream, in->data().data(), in->data().size(), reinterpret_cast<char *>(in->address()))) {
        stream << "Failed to write raw data." << std::endl;
        return CR_FAILURE;
    }
    return CR_OK;
}

static command_result write_string(color_ostream &stream, const WriteIn *in)
{
    if (!safe_write_string(stream, reinterpret_cast<void *>(in->address()), in->data())) {
        stream << "Failed to write string." << std::endl;
        return CR_FAILURE;
    }
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
