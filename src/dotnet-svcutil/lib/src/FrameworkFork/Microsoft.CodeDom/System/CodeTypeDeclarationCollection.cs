// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

namespace Microsoft.CodeDom
{
    using System;
    using System.Collections;
    using System.Runtime.InteropServices;


    /// <devdoc>
    ///     <para>
    ///       A collection that stores <see cref='Microsoft.CodeDom.CodeTypeDeclaration'/> objects.
    ///    </para>
    /// </devdoc>
    [
        //  ClassInterface(ClassInterfaceType.AutoDispatch),
        ComVisible(true),
    // Serializable,
    ]
    public class CodeTypeDeclarationCollection : CollectionBase
    {
        /// <devdoc>
        ///     <para>
        ///       Initializes a new instance of <see cref='Microsoft.CodeDom.CodeTypeDeclarationCollection'/>.
        ///    </para>
        /// </devdoc>
        public CodeTypeDeclarationCollection()
        {
        }

        /// <devdoc>
        ///     <para>
        ///       Initializes a new instance of <see cref='Microsoft.CodeDom.CodeTypeDeclarationCollection'/> based on another <see cref='Microsoft.CodeDom.CodeTypeDeclarationCollection'/>.
        ///    </para>
        /// </devdoc>
        public CodeTypeDeclarationCollection(CodeTypeDeclarationCollection value)
        {
            this.AddRange(value);
        }

        /// <devdoc>
        ///     <para>
        ///       Initializes a new instance of <see cref='Microsoft.CodeDom.CodeTypeDeclarationCollection'/> containing any array of <see cref='Microsoft.CodeDom.CodeTypeDeclaration'/> objects.
        ///    </para>
        /// </devdoc>
        public CodeTypeDeclarationCollection(CodeTypeDeclaration[] value)
        {
            this.AddRange(value);
        }

        /// <devdoc>
        /// <para>Represents the entry at the specified index of the <see cref='Microsoft.CodeDom.CodeTypeDeclaration'/>.</para>
        /// </devdoc>
        public CodeTypeDeclaration this[int index]
        {
            get
            {
                return ((CodeTypeDeclaration)(List[index]));
            }
            set
            {
                List[index] = value;
            }
        }

        /// <devdoc>
        ///    <para>Adds a <see cref='Microsoft.CodeDom.CodeTypeDeclaration'/> with the specified value to the 
        ///    <see cref='Microsoft.CodeDom.CodeTypeDeclarationCollection'/> .</para>
        /// </devdoc>
        public int Add(CodeTypeDeclaration value)
        {
            return List.Add(value);
        }

        /// <devdoc>
        /// <para>Copies the elements of an array to the end of the <see cref='Microsoft.CodeDom.CodeTypeDeclarationCollection'/>.</para>
        /// </devdoc>
        public void AddRange(CodeTypeDeclaration[] value)
        {
            if (value == null)
            {
                throw new ArgumentNullException("value");
            }
            for (int i = 0; ((i) < (value.Length)); i = ((i) + (1)))
            {
                this.Add(value[i]);
            }
        }

        /// <devdoc>
        ///     <para>
        ///       Adds the contents of another <see cref='Microsoft.CodeDom.CodeTypeDeclarationCollection'/> to the end of the collection.
        ///    </para>
        /// </devdoc>
        public void AddRange(CodeTypeDeclarationCollection value)
        {
            if (value == null)
            {
                throw new ArgumentNullException("value");
            }
            int currentCount = value.Count;
            for (int i = 0; i < currentCount; i = ((i) + (1)))
            {
                this.Add(value[i]);
            }
        }

        /// <devdoc>
        /// <para>Gets a value indicating whether the 
        ///    <see cref='Microsoft.CodeDom.CodeTypeDeclarationCollection'/> contains the specified <see cref='Microsoft.CodeDom.CodeTypeDeclaration'/>.</para>
        /// </devdoc>
        public bool Contains(CodeTypeDeclaration value)
        {
            return List.Contains(value);
        }

        /// <devdoc>
        /// <para>Copies the <see cref='Microsoft.CodeDom.CodeTypeDeclarationCollection'/> values to a one-dimensional <see cref='System.Array'/> instance at the 
        ///    specified index.</para>
        /// </devdoc>
        public void CopyTo(CodeTypeDeclaration[] array, int index)
        {
            List.CopyTo(array, index);
        }

        /// <devdoc>
        ///    <para>Returns the index of a <see cref='Microsoft.CodeDom.CodeTypeDeclaration'/> in 
        ///       the <see cref='Microsoft.CodeDom.CodeTypeDeclarationCollection'/> .</para>
        /// </devdoc>
        public int IndexOf(CodeTypeDeclaration value)
        {
            return List.IndexOf(value);
        }

        /// <devdoc>
        /// <para>Inserts a <see cref='Microsoft.CodeDom.CodeTypeDeclaration'/> into the <see cref='Microsoft.CodeDom.CodeTypeDeclarationCollection'/> at the specified index.</para>
        /// </devdoc>
        public void Insert(int index, CodeTypeDeclaration value)
        {
            List.Insert(index, value);
        }

        /// <devdoc>
        ///    <para> Removes a specific <see cref='Microsoft.CodeDom.CodeTypeDeclaration'/> from the 
        ///    <see cref='Microsoft.CodeDom.CodeTypeDeclarationCollection'/> .</para>
        /// </devdoc>
        public void Remove(CodeTypeDeclaration value)
        {
            List.Remove(value);
        }
    }
}
