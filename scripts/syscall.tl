#namespace venom.tl
@begin  
@msg hello betman
@var int a = 3
@var int b = 3
@alloc a = test
@loop
@wait 1
@if a == 10
@msg is it reall?
@msg bye
@endif
@elseif a == b
@msg cool guy!
@ass& str a = ctime()
@msg yes!
@endif
@else
@msg good
@endif
@endloop
@msg hello guys!
@end  
