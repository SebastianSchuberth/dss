/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.pdf.openpdf.visible;

import java.io.IOException;

import com.lowagie.text.Image;
import com.lowagie.text.Rectangle;
import com.lowagie.text.pdf.ColumnText;
import com.lowagie.text.pdf.PdfPCell;
import com.lowagie.text.pdf.PdfPTable;
import com.lowagie.text.pdf.PdfTemplate;

import eu.europa.esig.dss.pdf.visible.CommonDrawerUtils;
import eu.europa.esig.dss.pdf.visible.ImageAndResolution;
import eu.europa.esig.dss.pdf.visible.ImageUtils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;

public class ImageOnlySignatureDrawer extends AbstractITextSignatureDrawer {

	@Override
	public void draw() throws IOException {

		Image image = Image.getInstance(DSSUtils.toByteArray(parameters.getImage()));

		float zoom = parameters.getScaleFactor();
		int width = parameters.getWidth();
		int height = parameters.getHeight();
		
		ImageAndResolution ires = ImageUtils.readDisplayMetadata(parameters.getImage());
		if (width == 0) {
			width = (int) (image.getWidth() * CommonDrawerUtils.getPageScaleFactor(ires.getxDpi()));
		}
		if (height == 0) {
			height = (int) (image.getHeight() * CommonDrawerUtils.getPageScaleFactor(ires.getyDpi()));
		}
		width *= zoom;
		height *= zoom;

		if (Utils.isStringNotBlank(signatureFieldId)) {
			appearance.setVisibleSignature(signatureFieldId);
			Rectangle rect = appearance.getRect();
			if (rect != null) {
				width = (int) rect.getWidth();
				height = (int) rect.getHeight();
			}
		} else {
			Rectangle pageSize = appearance.getStamper().getReader().getPageSize(parameters.getPage());
			float originY = pageSize.getHeight();

			Rectangle rect = new Rectangle(parameters.getxAxis(), originY - parameters.getyAxis() - height, parameters.getxAxis() + width,
					originY - parameters.getyAxis());
			rect.setBackgroundColor(parameters.getBackgroundColor());
			appearance.setVisibleSignature(rect, parameters.getPage());
		}
		
		image.scaleAbsolute(width, height);

		PdfTemplate layer = appearance.getLayer(2);
		ColumnText ct = new ColumnText(layer);
		ct.setSimpleColumn(0, 0, width, height);
		
		PdfPTable table = new PdfPTable(1);
		table.setWidthPercentage(100);
		PdfPCell pdfPCell = new PdfPCell(image);
		pdfPCell.setBorder(PdfPCell.NO_BORDER);
		table.addCell(pdfPCell);
		
		ct.addElement(table);
		ct.go();
	}

}
