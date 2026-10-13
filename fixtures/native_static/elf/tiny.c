void _start(void) {
  __asm__ volatile("mov $60, %eax\n\txor %edi, %edi\n\tsyscall");
}
