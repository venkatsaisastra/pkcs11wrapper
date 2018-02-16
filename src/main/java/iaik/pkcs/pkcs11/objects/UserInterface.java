// Copyright (c) 2002 Graz University of Technology. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// 3. The end-user documentation included with the redistribution, if any, must
//    include the following acknowledgment:
//
//    "This product includes software developed by IAIK of Graz University of
//     Technology."
//
//    Alternately, this acknowledgment may appear in the software itself, if and
//    wherever such third-party acknowledgments normally appear.
//
// 4. The names "Graz University of Technology" and "IAIK of Graz University of
//    Technology" must not be used to endorse or promote products derived from
//    this software without prior written permission.
//
// 5. Products derived from this software may not be called "IAIK PKCS Wrapper",
//    nor may "IAIK" appear in their name, without prior written permission of
//    Graz University of Technology.
//
// THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESSED OR IMPLIED
// WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE LICENSOR BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
// OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
// OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
// ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

package iaik.pkcs.pkcs11.objects;

import java.io.UnsupportedEncodingException;

import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.Util;

/**
 * Objects of this class represent a user interface as specified by PKCS#11
 * v2.20.
 *
 * @author Florian Reimair
 * @version 1.0
 */
public class UserInterface extends HardwareFeature {

    private LongAttribute pixelX;
    private LongAttribute pixelY;
    private LongAttribute resolution;
    private LongAttribute charRows;
    private LongAttribute charColumns;
    private BooleanAttribute color;
    private LongAttribute bitsPerPixel;
    private ByteArrayAttribute charSets;
    private ByteArrayAttribute encodingMethods;
    private ByteArrayAttribute mimeTypes;

    /**
     * Default Constructor.
     */
    public UserInterface() {
        hardwareFeatureType.setLongValue(FeatureType.USER_INTERFACE);
    }

    /**
     * Called by getInstance to create an instance of a PKCS#11 user interface.
     *
     * @param session
     *          The session to use for reading attributes. This session must
     *          have the appropriate rights; i.e. it must be a user-session, if
     *          it is a private object.
     * @param objectHandle
     *          The object handle as given from the PKCS#111 module.
     * @exception TokenException
     *              If getting the attributes failed.
     */
    protected UserInterface(Session session, long objectHandle)
        throws TokenException {
        super(session, objectHandle);
        hardwareFeatureType.setLongValue(FeatureType.USER_INTERFACE);
    }

    /**
     * The getInstance method of the HardwareFeature class uses this method to
     * create an instance of a PKCS#11 user interface.
     *
     * @param session
     *          The session to use for reading attributes. This session must
     *          have the appropriate rights; i.e. it must be a user-session, if
     *          it is a private object.
     * @param objectHandle
     *          The object handle as given from the PKCS#111 module.
     * @return The object representing the PKCS#11 object.
     *         The returned object can be casted to the
     *         according sub-class.
     * @exception TokenException
     *              If getting the attributes failed.
     */
    public static PKCS11Object getInstance(Session session, long objectHandle)
        throws TokenException {
        return new UserInterface(session, objectHandle);
    }

    /**
     * Put all attributes of the given object into the attributes table of this
     * object. This method is only static to be able to access invoke the
     * implementation of this method for each class separately.
     *
     * @param object
     *          The object to handle.
     */
    protected static void putAttributesInTable(UserInterface object) {
        Util.requireNonNull("object", object);
        object.attributeTable.put(Attribute.PIXEL_X, object.pixelX);
        object.attributeTable.put(Attribute.PIXEL_Y, object.pixelY);
        object.attributeTable.put(Attribute.RESOLUTION, object.resolution);
        object.attributeTable.put(Attribute.CHAR_ROWS, object.charRows);
        object.attributeTable.put(Attribute.CHAR_COLUMNS, object.charColumns);
        object.attributeTable.put(Attribute.COLOR, object.color);
        object.attributeTable.put(Attribute.BITS_PER_PIXEL,
                object.bitsPerPixel);
        object.attributeTable.put(Attribute.CHAR_SETS, object.charSets);
        object.attributeTable.put(Attribute.ENCODING_METHODS,
                object.encodingMethods);
        object.attributeTable.put(Attribute.MIME_TYPES, object.mimeTypes);
    }

    /**
     * Allocates the attribute objects for this class and adds them to the
     * attribute table.
     */
    @Override
    protected void allocateAttributes() {
        super.allocateAttributes();

        pixelX = new LongAttribute(Attribute.PIXEL_X);
        pixelY = new LongAttribute(Attribute.PIXEL_Y);
        resolution = new LongAttribute(Attribute.RESOLUTION);
        charRows = new LongAttribute(Attribute.CHAR_ROWS);
        charColumns = new LongAttribute(Attribute.CHAR_COLUMNS);
        color = new BooleanAttribute(Attribute.COLOR);
        bitsPerPixel = new LongAttribute(Attribute.BITS_PER_PIXEL);
        charSets = new ByteArrayAttribute(Attribute.CHAR_SETS);
        encodingMethods = new ByteArrayAttribute(Attribute.ENCODING_METHODS);
        mimeTypes = new ByteArrayAttribute(Attribute.MIME_TYPES);

        putAttributesInTable(this);
    }

    @Override
    public boolean equals(Object otherObject) {
        if (this == otherObject) {
            return true;
        } else if (!super.equals(otherObject)) {
            return false;
        } else if (getClass() != otherObject.getClass()) {
            return false;
        }

        UserInterface other = (UserInterface) otherObject;
        return Util.objEquals(this.bitsPerPixel, other.bitsPerPixel)
                && Util.objEquals(this.charColumns, other.charColumns)
                && Util.objEquals(this.charRows, other.charRows)
                && Util.objEquals(this.charSets, other.charSets)
                && Util.objEquals(this.color, other.color)
                && Util.objEquals(this.encodingMethods, other.encodingMethods)
                && Util.objEquals(this.mimeTypes, other.mimeTypes)
                && Util.objEquals(this.mimeTypes, other.mimeTypes)
                && Util.objEquals(this.pixelX, other.pixelX)
                && Util.objEquals(this.pixelY, other.pixelY)
                && Util.objEquals(this.resolution, other.resolution);
    }

    /**
     * Gets the pixel x.
     *
     * @return the pixel x
     */
    public LongAttribute getPixelX() {
        return this.pixelX;
    }

    /**
     * Gets the pixel y.
     *
     * @return the pixel y
     */
    public LongAttribute getPixelY() {
        return pixelY;
    }

    /**
     * Gets the resolution.
     *
     * @return the resolution
     */
    public LongAttribute getResolution() {
        return resolution;
    }

    /**
     * Gets the char rows.
     *
     * @return the char rows
     */
    public LongAttribute getCharRows() {
        return charRows;
    }

    /**
     * Gets the char columns.
     *
     * @return the char columns
     */
    public LongAttribute getCharColumns() {
        return charColumns;
    }

    /**
     * Gets the color.
     *
     * @return the color
     */
    public BooleanAttribute getColor() {
        return color;
    }

    /**
     * Gets the bits per pixel.
     *
     * @return the bits per pixel
     */
    public LongAttribute getBitsPerPixel() {
        return bitsPerPixel;
    }

    /**
     * Gets the char sets.
     *
     * @return the char sets
     */
    public ByteArrayAttribute getCharSets() {
        return charSets;
    }

    /**
     * Gets the encoding methods.
     *
     * @return the encoding methods
     */
    public ByteArrayAttribute getEncodingMethods() {
        return encodingMethods;
    }

    /**
     * Gets the mime types.
     *
     * @return the mime types
     */
    public ByteArrayAttribute getMimeTypes() {
        return mimeTypes;
    }

    /**
     * The overriding of this method should ensure that the objects of this
     * class work correctly in a hashtable.
     *
     * @return The hash code of this object.
     */
    @Override
    public int hashCode() {
        return pixelX.hashCode() ^ pixelY.hashCode() ^ resolution.hashCode()
            ^ charRows.hashCode() ^ charColumns.hashCode() ^ color.hashCode()
            ^ bitsPerPixel.hashCode() ^ charSets.hashCode()
            ^ encodingMethods.hashCode() ^ mimeTypes.hashCode();
    }

    /**
     * Read the values of the attributes of this object from the token.
     *
     * @param session
     *          The session to use for reading attributes. This session must
     *          have the appropriate rights; i.e. it must be a user-session, if
     *          it is a private object.
     * @exception TokenException
     *              If getting the attributes failed.
     */
    @Override
    public void readAttributes(Session session)
        throws TokenException {
        super.readAttributes(session);

        PKCS11Object.getAttributeValues(session, objectHandle, new Attribute[] {
            pixelX, pixelY, resolution, charRows, charColumns, color,
            bitsPerPixel, charSets, encodingMethods, mimeTypes });
    }

    /**
     * Returns a string representation of the current object. The
     * output is only for debugging purposes and should not be used for other
     * purposes.
     *
     * @return A string presentation of this object for debugging output.
     */
    @Override
    public String toString() {
        String superToString = super.toString();
        return Util.concatObjectsCap(superToString.length() + 100, superToString,
                "\n  Pixel X: ", pixelX.getValueString(),
                "\n  Pixel Y: ", pixelY.getValueString(),
                "\n  Resolution: ", resolution.getValueString(),
                "\n  Char Rows: ", charRows.getValueString(),
                "\n  Char Columns: ", charColumns.getValueString(),
                "\n  Color: ", color.getValueString(),
                "\n  Bits per Pixel: ", bitsPerPixel.getValueString(),
                "\n  Char sets:", toString(charSets),
                "\n  Encoding methods: ", toString(encodingMethods),
                "\n  Mime Types: ", toString(mimeTypes));
    }
    
    private static String toString(ByteArrayAttribute attr) {
        try {
            return new String(attr.getByteArrayValue(), "ASCII");
        } catch (UnsupportedEncodingException ex) {
            return new String(attr.getByteArrayValue());
        }
    }
}
