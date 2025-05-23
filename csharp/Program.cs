using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using System.Xml.XPath;

class Program
{
    static void Main(string[] args)
    {
        string samplesFolder = "../samples";
        string[] xmlFiles = Directory.GetFiles(samplesFolder, "*.xml");

        foreach (var xmlPath in xmlFiles)
        {
            Console.WriteLine($"Processing file: {xmlPath}");
            try
            {
                string serialized;
                var base64Digest = getSignedPropertiesDigest(xmlPath, out serialized);
                Console.WriteLine("Serialized XML:");
                Console.WriteLine(serialized);
                Console.WriteLine("\nSHA256 Digest (base64):");
                Console.WriteLine(base64Digest);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error processing file {xmlPath}: {ex.Message}");
            }
            Console.WriteLine("------------------------------------------------");
        }

        static string getSignedPropertiesDigest(string fileName, out string serialized)
        {
            string xpath = "//*[@Id='id-xades-signed-props']";

            // Load the XML document
            var doc = new XmlDocument();
            doc.PreserveWhitespace = false; // Removes indentation/extra spaces
            doc.Load(fileName);

            // Set up namespace manager (required for XPath with prefixes)
            var nsmgr = new XmlNamespaceManager(doc.NameTable);
            nsmgr.AddNamespace("xades", "http://uri.etsi.org/01903/v1.3.2#");

            // Select the node
            var node = doc.SelectSingleNode(xpath, nsmgr);
            if (node == null)
            {
                throw new Exception("Node not found - xpath: " + xpath);
            }

            // Linearize the node: remove whitespace, compact output
            var settings = new XmlWriterSettings
            {
                OmitXmlDeclaration = true,
                Indent = false,
                NewLineHandling = NewLineHandling.None
            };

            using (var sw = new StringWriter())
            using (var xw = XmlWriter.Create(sw, settings))
            {
                node.WriteTo(xw);
                xw.Flush();
                serialized = sw.ToString();
            }

            // Hash the UTF-8 bytes of the serialized XML
            byte[] data = Encoding.UTF8.GetBytes(serialized);
            byte[] hash = SHA256.Create().ComputeHash(data);
            return Convert.ToBase64String(hash);
        }
    }
}