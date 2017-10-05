#ifndef _INL_HOOK_H
#define _INL_HOOK_H

int inl_sethook(void **orig, void *hook);
int inl_unhook(void *hook);
int inl_within_trampoline(unsigned long address);

#endif

