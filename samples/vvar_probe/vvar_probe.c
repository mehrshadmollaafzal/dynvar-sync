#include <intrin.h>
#include <stdint.h>
#include <stdio.h>

volatile uint64_t g_original_value;
volatile uint64_t g_replacement_value;
volatile uint64_t g_stack_observed;
volatile uint32_t g_constant_observed;

extern uint64_t vvar_register_probe(uint32_t seed);
extern uint64_t vvar_stack_probe(uint64_t seed);
extern uint32_t vvar_constant_probe(void);

__declspec(noinline) static uint64_t c_stack_local_probe(uint64_t seed)
{
    volatile uint64_t stack_local = seed ^ UINT64_C(0x1122334455667788);
    __debugbreak();
    return stack_local + 1;
}

__declspec(noinline) static uint32_t c_constant_local_probe(void)
{
    volatile uint32_t constant_local = 2;
    __debugbreak();
    return constant_local;
}

int main(void)
{
    uint64_t register_result = vvar_register_probe(0x40);
    uint64_t stack_result = vvar_stack_probe(UINT64_C(0x8877665544332211));
    uint32_t constant_result = vvar_constant_probe();
    uint64_t c_stack_result = c_stack_local_probe(UINT64_C(0x55));
    uint32_t c_constant_result = c_constant_local_probe();

    printf(
        "register=%llx stack=%llx constant=%x c_stack=%llx c_constant=%x\n",
        (unsigned long long)register_result,
        (unsigned long long)stack_result,
        constant_result,
        (unsigned long long)c_stack_result,
        c_constant_result
    );
    return 0;
}
