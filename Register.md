# My Smali Analysis Tool

When I started working with Smali code, the biggest problem I faced was remembering what was stored in a given register 100 lines ago. The paper-and-pencil method I was using couldn't cut it; it was impossible.

So, I started looking for static analysis register-tracking tools that take snapshots of a given register's values so you can go back and look them up. To my surprise, there were none.

Without such a tool, it would be impossible to deduce the logic hidden in thousands of lines of code, so I decided to build it. It is not fancy and could be improved, but it actually solves a tangible problem that currently lacks a better solution.

Here is what you can do with this tool.

## Adding a Class

When you open the app, the first page will let you add a class or open an already tracked class.

<img width="1914" height="977" alt="image" src="https://github.com/user-attachments/assets/b9b9d470-db76-4bc4-97bb-3cbaa16e6899" />
<img width="1913" height="975" alt="Click here to add Class" src="https://github.com/user-attachments/assets/dfd74ea6-89e8-4549-84e3-61c5b990e8d9" />

Once you click the Create button, you will be required to insert:

- **Name:** The name you want to give to the class. This doesn't have to match the real class name; most of the classes I found are obfuscated, so adding a logical name makes things much easier.
- **ClassPath**
- **Obfuscated name/real name** of the class.

<img width="1911" height="969" alt="Untitled design" src="https://github.com/user-attachments/assets/88428773-a7b9-4391-8141-d1436d9626af" />

Click Create to create the class!

## Adding a Method

After creating a class, you will be inside the class, and from there, you can add a method.

- You can add a name for the method, and you can leave a description for your method, as I did.

<img width="1919" height="963" alt="Put the name of the function here" src="https://github.com/user-attachments/assets/0a385627-8223-45d8-96d1-0c57d07eb3f6" />

## Inside a Method

This is the core of the tool.

- On the **left side**, you can take notes and mention registers, which are hoverable to display the value they had in that line.
- On the **right side,** you assign values to registers. For now, the registers can be a `null`, an `int`, or a `String`.

There are two types of registers: parameter registers and local registers. The `+p` button adds a parameter register, and +v adds a local register.

<img width="1907" height="911" alt="Your paragraph text" src="https://github.com/user-attachments/assets/e37a2267-c29b-42b6-8c44-449266b3ee2f" />

### Using the Tool

- In the `script` space, you use the syntax `register_name = value ; register_name = value` to assign values to registers.
- Then, by naming the register in the `note` space and hovering over it, you can see the value it had at that line in the past.
- Assigning a new value to a register only changes the register's current state; the snapshot history is saved and can be accessed by hovering over older lines in your note.

<img width="1914" height="977" alt="historical" src="https://github.com/user-attachments/assets/988aebf3-31ae-46ef-a16f-831f1b6c4bc8" />

For now, that is what this tool can do. Even though it is lightweight, it has served its purpose as my personal tool. However, I don't plan to stop here; I plan to add many features, such as:

- "Go to" functionality (with lines)
- Conditionals
- Global variables
- Referenceable methods
