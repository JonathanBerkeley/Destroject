# Destroject
Windows multiple DLL process injector     

[UnknownCheats mirror](https://www.unknowncheats.me/forum/general-programming-and-reversing/491785-injector-multiple-dlls-interface-windows-manualmap-traditional.html)    
Built as part of the [Quack](https://github.com/JonathanBerkeley/quack) project    

# Usage
1. Place injector in a folder with DLL(s)    
2. Open command prompt / powershell in the folder     
3. Execute injector through command-line arguments with the name of the target process.
E.G:    
   C:\Users\Me\Desktop> Destroject64.exe "ProcessName"    
   Or for manual map injection:    
   C:\Users\Me\Desktop> Destroject64.exe "ProcessName" manual    

After running the first time through command-line, it will save the last entered process and injection mode.    
To inject into the same process again with the same injection mode, the injector can just be run directly.    
To inject into a different process or use a different injection mode, do Step 2 and 3 again.    

**For 32 bit target processes use Destroject32, for 64 bit target processes use Destroject64**    

# Inject .DLL after building it, in Visual Studio
Right click solution -> Properties -> Configuration Properties -> Build Events -> Post-Build Event -> Command Line:    
> cd C:\Users\Me\Desktop    
> start Destroject64.exe "ProcessName"    

C:\Users\Me\Desktop is a placeholder for the location of the injector + .DLL(s)    

"ProcessName" is a placeholder for the name of the target process -- use the underlying .exe name, you can find this using task manager (right-click process -> properties)    

# Tutorial
[![Tutorial](https://i.imgur.com/nj3qE5S.png)](https://www.youtube.com/watch?v=j0_t6Hu9I1w)    
