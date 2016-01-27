// copyright.scala

import java.io.File

object doIt {
  def main(args:Array[String]) {
    update(new File(args(0)))
  }

  def update(file:File) {
    println("Reading file " + file.getAbsolutePath())
    if (file.isFile() && file.getName().endsWith(".java")) {
      val string = scala.io.Source.fromFile(file.getAbsolutePath()).mkString

      if (string startsWith oldString) {
        println("Found old copyright at " + file.getAbsolutePath())
        printToFile(newString + string.substring(oldString.length), file.getAbsolutePath())
      } else if (!(string startsWith newString)) {
        printToFile(newString + "\n\n" + string, file.getAbsolutePath)
      }
    } else if (file.isDirectory() && !file.getName().startsWith(".")) {
      // directory

      file.listFiles().foreach { update }
    }
  }

  val oldString = """////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2015 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 2.0 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is ThreadFix.
//
//     The Initial Developer of the Original Code is Denim Group, Ltd.
//     Portions created by Denim Group, Ltd. are Copyright (C)
//     Denim Group, Ltd. All Rights Reserved.
//
//     Contributor(s): Denim Group, Ltd.
//
////////////////////////////////////////////////////////////////////////"""

val newString = """////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2016 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 2.0 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is ThreadFix.
//
//     The Initial Developer of the Original Code is Denim Group, Ltd.
//     Portions created by Denim Group, Ltd. are Copyright (C)
//     Denim Group, Ltd. All Rights Reserved.
//
//     Contributor(s): Denim Group, Ltd.
//
////////////////////////////////////////////////////////////////////////"""

  def printToFile(content: String, location: String) =
    Some(new java.io.PrintWriter(location)).foreach{f => try{f.write(content)}finally{f.close}}

}