using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace FTPNet
{
    public class IOElement : IComparable    
    {
        public string Name { get; set; }
        public string LastEdit { get; set; }
        public string Path { get; set; }

        public ulong Size { get; set; }
        public int Rigths { get; set; }
        public string RigthsString { get; set; }
        public string Owner { get; set; }
        public string Group { get; set; }
        public bool IsFile { get; set; }
        public string FileType { get; set; }

        public static List<IOElement> ParseWindowsFiles(string rawList, bool addCurrentDirectory = true, bool addParentDirectory = true)
        {
            List<IOElement> files = new List<IOElement>();

            foreach (string item in rawList.Trim().Split('\n'))
            {
                IOElement newElement = new IOElement();

                string trimmedItem = item.Trim();

                int timeEnding = 0;

                for (int i = 8; i < trimmedItem.Length; i++)
                {
                    if (trimmedItem[i] != ' ')
                    {
                        for (int j = i; j < trimmedItem.Length; j++)
                        {
                            if (trimmedItem[i] == ' ')
                            {
                                timeEnding = j;
                                break;
                            }
                        }
                    }
                }

                newElement.LastEdit = trimmedItem.Substring(0, timeEnding).Trim();
                while (newElement.LastEdit.Contains("  "))
                    newElement.LastEdit = newElement.LastEdit.Replace("  ", " ");

                int typeBeginning = 0;
                int typeEnding = 0;

                for (int i = 17; i < trimmedItem.Length; i++)
                {
                    if (trimmedItem[i] != ' ')
                    {
                        typeBeginning = i;
                        break;
                    }
                }

                for (int i = typeBeginning; i < trimmedItem.Length; i++)
                {
                    if (trimmedItem[i] == ' ')
                    {
                        typeEnding = i;
                        break;
                    }
                }

                newElement.FileType = trimmedItem.Substring(typeBeginning, typeEnding - typeBeginning).Replace("<DIR>", "Directory");

                newElement.IsFile = newElement.FileType != "Directory";

                int nameBeginning = 0;
                for (int i = typeEnding + 1; i < trimmedItem.Length; i++)
                {
                    if (trimmedItem[i] != ' ')
                    {
                        nameBeginning = i;
                        break;
                    }
                }

                newElement.Name = trimmedItem.Substring(nameBeginning, trimmedItem.Length - nameBeginning);

                ulong size = 0;
                ulong.TryParse(newElement.FileType, out size);

                newElement.Size = size;

                if (size != 0)
                    newElement.FileType = newElement.Name.Split('.').Last();

                if (newElement.Name == ".")
                    addCurrentDirectory = false;
                if (newElement.Name == "..")
                    addParentDirectory = false;

                if (newElement.IsFile)
                {
                    if (newElement.Name.Contains('.'))
                        newElement.FileType = newElement.Name.Substring(newElement.Name.LastIndexOf('.'));
                    else
                        newElement.FileType = newElement.Name;
                }

                files.Add(newElement);
            }

            if (addCurrentDirectory)
            {
                IOElement newElement = new IOElement();
                newElement.Name = ".";
                newElement.FileType = "Directory";
                newElement.IsFile = false;
                newElement.Size = 2048;
                files.Add(newElement);
            }

            if (addParentDirectory)
            {
                IOElement newElement = new IOElement();
                newElement.Name = "..";
                newElement.FileType = "Directory";
                newElement.IsFile = false;
                newElement.Size = 2048;
                files.Add(newElement);
            }

            return files;
        }

        public static List<IOElement> ParseLinuxFiles(string rawList, bool addCurrentDirectory = true, bool addParentDirectory = true)
        {
            List<IOElement> files = new List<IOElement>();

            foreach (string item in rawList.Trim().Split('\n'))
            {
                IOElement newElement = new IOElement();

                string trimmedItem = item.Trim();

                string tmp = trimmedItem.Substring(0, trimmedItem.IndexOf(' ')).Trim();

                trimmedItem = trimmedItem.Remove(0, trimmedItem.IndexOf(' '));

                newElement.IsFile = tmp.StartsWith("d") ? false : true;

                int ownerNumber = 0;
                int groupNumber = 0;
                int publicNumber = 0;

                if (tmp[1] == 'r')
                    ownerNumber += 4;
                if (tmp[2] == 'w')
                    ownerNumber += 2;
                if (tmp[3] == 'x')
                    ownerNumber += 1;

                if (tmp[4] == 'r')
                    groupNumber += 4;
                if (tmp[5] == 'w')
                    groupNumber += 2;
                if (tmp[6] == 'x')
                    groupNumber += 1;

                if (tmp[7] == 'r')
                    publicNumber += 4;
                if (tmp[8] == 'w')
                    publicNumber += 2;
                if (tmp[9] == 'x')
                    publicNumber += 1;

                newElement.Rigths = ownerNumber * 100 + groupNumber * 10 + publicNumber;
                newElement.RigthsString = newElement.Rigths.ToString();

                trimmedItem = trimmedItem.Trim();

                string trash = trimmedItem.Substring(0, trimmedItem.IndexOf(' '));
                trimmedItem = trimmedItem.Remove(0, trimmedItem.IndexOf(' ')).Trim();
                newElement.Owner = trimmedItem.Substring(0, trimmedItem.IndexOf(' '));

                trimmedItem = trimmedItem.Remove(0, trimmedItem.IndexOf(' ')).Trim();
                newElement.Group = trimmedItem.Substring(0, trimmedItem.IndexOf(' '));

                trimmedItem = trimmedItem.Remove(0, trimmedItem.IndexOf(' ')).Trim();
                newElement.Size = ulong.Parse(trimmedItem.Substring(0, trimmedItem.IndexOf(' ')));

                trimmedItem = trimmedItem.Remove(0, trimmedItem.IndexOf(' ')).Trim();
                newElement.LastEdit = trimmedItem.Substring(0, trimmedItem.IndexOf(' '));

                trimmedItem = trimmedItem.Remove(0, trimmedItem.IndexOf(' ')).Trim();
                newElement.LastEdit += "." + trimmedItem.Substring(0, trimmedItem.IndexOf(' '));

                trimmedItem = trimmedItem.Remove(0, trimmedItem.IndexOf(' ')).Trim();
                newElement.LastEdit += "." + trimmedItem.Substring(0, trimmedItem.IndexOf(' '));

                trimmedItem = trimmedItem.Remove(0, trimmedItem.IndexOf(' ')).Trim();

                newElement.Name = trimmedItem;

                if (newElement.Name == ".")
                    addCurrentDirectory = false;

                if (newElement.Name == "..")
                    addParentDirectory = false;

                if (newElement.IsFile == false)
                    newElement.FileType = "Directory";
                else
                {
                    if (newElement.Name.Contains("."))
                        newElement.FileType = newElement.Name.Substring(newElement.Name.LastIndexOf('.'));
                    else
                        newElement.FileType = newElement.Name;
                }

                files.Add(newElement);
            }

            if (addCurrentDirectory)
            {
                IOElement newElement = new IOElement();
                newElement.Name = ".";
                newElement.FileType = "Directory";
                newElement.IsFile = false;
                newElement.Size = 2048;
                files.Add(newElement);
            }

            if (addParentDirectory)
            {
                IOElement newElement = new IOElement();
                newElement.Name = "..";
                newElement.FileType = "Directory";
                newElement.IsFile = false;
                newElement.Size = 2048;
                files.Add(newElement);
            }

            return files;
        }

        public int CompareTo(object obj)
        {
            IOElement item = (IOElement)obj;

            if (this.IsFile)
            {
                return item.IsFile ? this.Name.CompareTo(item.Name) : 1;
            }
            else
            {
                return !item.IsFile ? this.Name.CompareTo(item.Name) : -1;
            }
        }
    }
}
