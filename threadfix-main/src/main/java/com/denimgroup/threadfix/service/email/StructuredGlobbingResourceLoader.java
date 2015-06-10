/*
 * Copyright 2000-2004 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License")
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.denimgroup.threadfix.service.email;
import org.apache.velocity.tools.view.WebappResourceLoader;

import java.io.FilterInputStream;
import java.io.InputStream;
import java.io.IOException;

//this class will strip indentation and newlines from templates at loading time
//explanation is provided here http://stackoverflow.com/a/30228437/4871809
public class StructuredGlobbingResourceLoader extends WebappResourceLoader
{

  public static class VTLIndentationGlobber extends FilterInputStream
  {
    protected String buffer = "";
    protected int bufpos = 0;
    protected enum State
    {
        bol, content, eol1, eol2, eof
    }
    //protected State state = State.defstate;
    protected State state = State.bol;

    public VTLIndentationGlobber(InputStream is)
    {
      super(is);
    }

    public int read() throws IOException {
        switch(state)
        {
          case bol://read until non indentation character
            while(true){
                int ch = in.read();
                if (ch!=(int)' ' && ch!=(int)'\t'){
                    state = State.content;
                    return processChar(ch);
                }
            }

          case content: {
                int ch = in.read();
                return processChar(ch);
          }

          //eol states replace all "\n" by "##\n"
          case eol1:
            state = State.eol2;
            return (int)'#';

          case eol2:
            state = State.bol;
            return (int)'\n';

          case eof:
            return -1;
        }
		return -1;
    }

    //Return the normal character if not end of file or \n
    private int processChar(int ch){
        switch(ch){
            case -1:
                state = State.eof;
                return -1;
            case (int)'\n':
                state = State.eol1;
                return (int)'#';
            default:
                return ch;
        }
    }


    public int read(byte[] b, int off, int len) throws IOException
    {
      int i;
      int ok = 0;
      while (len-- > 0) {
        i = read();
        if (i == -1) return (ok == 0) ? -1 : ok;
        b[off++] = (byte) i;
        ok++;
      }
      return ok;
    }

    public int read(byte[] b) throws IOException
    {
      return read(b,0,b.length);
    }

    public boolean markSupported()
    {
      return false;
    }
  }

  public synchronized InputStream getResourceStream(String name)
  {
    return new VTLIndentationGlobber(super.getResourceStream(name));
  }

  // test
  public static void main(String args[])
  {
    try
    {
      java.io.BufferedReader reader = new java.io.BufferedReader(new java.io.InputStreamReader(new VTLIndentationGlobber(new java.io.FileInputStream(args[0]))));
      String line;
      while( (line = reader.readLine() ) != null )
      {
        System.out.println(line);
      }
    }
    catch(IOException ioe)
    {
      ioe.printStackTrace();
    }
  }

}
