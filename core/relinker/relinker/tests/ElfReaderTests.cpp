#include <relinker/parsing/ElfReader.hpp>
#include <cstring>
#include <functional>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

template<typename TValue>
void write(std::vector<std::uint8_t>& bytes, std::size_t offset, TValue value) {
    if (offset > bytes.size() || sizeof(value) > bytes.size() - offset) throw std::runtime_error("ELF fixture write is out of bounds");
    std::memcpy(bytes.data() + offset, &value, sizeof(value));
}

void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

void requireFailure(const std::function<void()>& operation, const std::string& expected) {
    try {
        operation();
    } catch (const Relinker::RelinkerException& error) {
        require(std::string(error.what()).find(expected) != std::string::npos, "ELF reader returned the wrong diagnostic");
        return;
    }
    throw std::runtime_error("ELF reader accepted an invalid section table");
}

std::vector<std::uint8_t> fixture() {
    std::vector<std::uint8_t> bytes(0xc3);
    bytes[0] = 0x7f;
    bytes[1] = 'E';
    bytes[2] = 'L';
    bytes[3] = 'F';
    bytes[4] = 2;
    bytes[5] = 1;
    write<std::uint64_t>(bytes, 0x28, 0x40);
    write<std::uint16_t>(bytes, 0x3a, 64);
    write<std::uint16_t>(bytes, 0x3c, 2);
    write<std::uint16_t>(bytes, 0x3e, 1);
    write<std::uint32_t>(bytes, 0x80, 1);
    write<std::uint32_t>(bytes, 0x84, 3);
    write<std::uint64_t>(bytes, 0x98, 0xc0);
    write<std::uint64_t>(bytes, 0xa0, 3);
    bytes[0xc0] = 0;
    bytes[0xc1] = 'x';
    bytes[0xc2] = 0;
    return bytes;
}

}

int main() {
    const auto valid = fixture();
    const auto headers = Relinker::ElfReader(valid).ReadSectionHeaders();
    require(headers.size() == 2 && headers[0].Name.empty() && headers[1].Name == "x", "ELF reader rejected a valid section table");

    for (const std::uint16_t size : {std::uint16_t{0}, std::uint16_t{63}, std::uint16_t{65}}) {
        auto bytes = valid;
        write(bytes, 0x3a, size);
        requireFailure([&] { Relinker::ElfReader(bytes).ReadSectionHeaders(); }, "section header entry size");
    }

    auto bytes = valid;
    write<std::uint16_t>(bytes, 0x3e, 2);
    requireFailure([&] { Relinker::ElfReader(bytes).ReadSectionHeaders(); }, "string table index");

    bytes = valid;
    write<std::uint32_t>(bytes, 0x80, 3);
    requireFailure([&] { Relinker::ElfReader(bytes).ReadSectionHeaders(); }, "name offset");

    bytes = valid;
    write<std::uint64_t>(bytes, 0xa0, 2);
    requireFailure([&] { Relinker::ElfReader(bytes).ReadSectionHeaders(); }, "not NUL-terminated");

    bytes = valid;
    write<std::uint64_t>(bytes, 0x98, 0xc2);
    requireFailure([&] { Relinker::ElfReader(bytes).ReadSectionHeaders(); }, "string table is out of bounds");
}
