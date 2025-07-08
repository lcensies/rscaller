



typedef union {
	char * char_ptr_type;
	int int_type;
	umode_t umode_t_type;
	compat_uptr_t * compat_uptr_t_ptr_type;
} SyscallParam;

enum ParamType {
	CHAR_PTR_TYPE = 0,
	INT_TYPE = 1,
	UMODE_T_TYPE = 2,
	COMPAT_UPTR_T_PTR_TYPE = 3,
};

void fetch_param_variant(SyscallParam *src, int param_type, void **param, size_t *param_size) {
	switch (param_type) {
		case CHAR_PTR_TYPE: *param = &src->char_ptr_type; *param_size = sizeof(src->char_ptr_type); return;
		case INT_TYPE: *param = &src->int_type; *param_size = sizeof(src->int_type); return;
		case UMODE_T_TYPE: *param = &src->umode_t_type; *param_size = sizeof(src->umode_t_type); return;
		case COMPAT_UPTR_T_PTR_TYPE: *param = &src->compat_uptr_t_ptr_type; *param_size = sizeof(src->compat_uptr_t_ptr_type); return;	}
	*param = (void*)&src->char_ptr_type; param_type = sizeof(src->char_ptr_type);

}
const SyscallSignature signature__x64_sys_open= { 3,	 {{CHAR_PTR_TYPE,true},{INT_TYPE,false},{UMODE_T_TYPE,false},}};
const SyscallSignature signature__x64_sys_openat= {	 4,	 {{INT_TYPE,false},{CHAR_PTR_TYPE,true},{INT_TYPE,false},{UMODE_T_TYPE,false},}};
static const SyscallSignature signature__x64_sys_execve = {	 3,	{{CHAR_PTR_TYPE,true},{COMPAT_UPTR_T_PTR_TYPE,true},{COMPAT_UPTR_T_PTR_TYPE,true},}};

