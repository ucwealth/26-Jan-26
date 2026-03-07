using System;
using System.IO;

namespace HelloWorld
{
    class Program
    {
        static void Main(string[] args)
        {
            Person myPerson = new Person();
            myPerson.Name = "Faye";
            Console.WriteLine(" ------------------- ");
            Console.WriteLine(myPerson.Name);  

            // files
            myPerson.filemon

            Pig myPig = new Pig();
            myPig.animalSound();
            Console.WriteLine(" ------------------- ");

            // enums
            int myApril = (int) Months.April;
            Months myMay = Months.May;
            int myJuly = (int) Months.July;
            Console.WriteLine(myApril);
            Console.WriteLine(myMay);
            Console.WriteLine(myJuly);

            Basics();
            Primi();
        }

    static void Basics()
        {
            int x = 5, y = 6, z = 7; // int = 4 bytes
            int a, b, c;
            a = b = c = 13;
            long myNum = 15000000000L; // long = 8 bytes
            float myFloat = 5.75F; // float = 4 bytes
            double myDoubleNum = 5.99D; // double = 8 bytes
            char myLetter = 'D'; // char = 2 bytes 
            bool myBool = true; // bool = 1 byte
            const string myText = "Hello"; // string = 2 bytes per character 
            // Console.WriteLine(myText);  
            // Console.WriteLine(a + b + c);
            Console.WriteLine(" ");

        }

    static void Primi()
        {
            /*
            Implicit Casting - (automatically) - converting a smaller type to a larger type size
            char -> int -> long -> float -> double

            Explicit Casting (manually) - converting a larger type to a smaller size type
            double -> float -> long -> int -> char
            - Methods for explicit casting:
            - Convert.ToBoolean, Convert.ToDouble, Convert.ToString, 
            - Convert.ToInt32 (int) and Convert.ToInt64 (long):
            - &&, || 
            - String methods = indexOf(char), Substring(idx)
            - \n newline, \t tab, \b backspace
            - fields and methods 

            - Encapsulation: To make sure sensitive data is hidden from unauthorized access.
            - Sealed: If you don't want other classes to inherit from a class, use the sealed keyword:
            - Polymorphism occurs when we have many classes that are related to each other by inheritance. This can be achieved through interfaces.
            - Types of polymorphism: method overriding and method overloading
            - To override base class method in the derived class, add virtual to the base and add override to the derived
            - Data abstraction is the process of hiding certain details and showing only essential information to the user.
            - Abstraction can be achieved with either abstract classes or interfaces(these 2 cant create objects)
            - 

            */

            // get user input 
            Console.WriteLine(" ");
            Console.WriteLine(Math.Min(5, 10) + Math.Max(3, 8));
            Console.WriteLine(Math.Max(3, 8));
            Console.WriteLine(" ");

            string firstName = "John";
            string lastName = "Doe";
            string name = string.Concat(firstName, lastName);
            string name2 = $"My full name is: {firstName} {lastName}";

            Console.WriteLine(name);
            Console.WriteLine(name2);
            Console.WriteLine(" ");

            string txt = "Hello World";
            Console.WriteLine(txt.ToUpper());   // Outputs "HELLO WORLD"
            Console.WriteLine(txt.ToLower());   // Outputs "hello world"

            // Console.WriteLine("Enter username:");
            // string userName = Console.ReadLine();
            // Console.WriteLine("Enter your age:");
            // int age = Convert.ToInt32(Console.ReadLine());
            // Console.WriteLine("Your username is: " + userName + " and your age is: " + age);
            Console.WriteLine(" ");

            // Conditionals
            int time = 20;
            if (time < 18) 
            {
                Console.WriteLine("Good day.");
            } 
            else 
            {
                Console.WriteLine("Good evening.");
            }

            // Switch
            int day = 4;
            switch (day)
            {
                case 1:
                    Console.WriteLine("Monday");
                    break;
                case 2:
                    Console.WriteLine("Tuesday");
                    break;
                case 3:
                    Console.WriteLine("Wednesday");
                    break;
                default:
                    Console.WriteLine("Looking forward to the Weekend.");
                    break;
            }

            // for...each
            string[] cars = {"Volvo", "BMW", "Ford", "Mazda"};
            cars[2] = "Opel";
            Array.Sort(cars);
            Console.WriteLine(cars.Length);
            foreach (string i in cars) 
            {
                Console.WriteLine(i);
            }
            
            int[] myNumbers = {1,2,3,4};
            Console.WriteLine(myNumbers.Sum());

        }

    }

    class Person
    {
        public string Name  // property
        { get; set; }

        // File methods
        /*
            AppendText(), Copy(), Delete(), Create() Creates or overwrites a file, 
            Exists(), ReadAllText(), Replace(), WriteAllText()
        */

        // Write to a file 
        public void filemon()
        {
            string sampleText = "Lorem Ipsum Dipsum Dipshiiii!!";
            // Create a file and write the content of sampleText to it
            File.WriteAllText("uselessFile.txt", sampleText);  

            string readText = File.ReadAllText("uselessFile.txt"); 
            Console.WriteLine(readText);  
        }

    }

}

// Interface
interface IAnimal 
{
  void animalSound(); 
}

class Pig : IAnimal 
{
  public void animalSound() 
  {
    Console.WriteLine("The pig says: oink oink");
  }
}

// Enumeration
enum Months
{
  January,    // 0
  February,   // 1
  March,      // 2
  April,      // 3
  May,        // 4
  June=31,    // 5
  July,       // 6
  August      // 7
}