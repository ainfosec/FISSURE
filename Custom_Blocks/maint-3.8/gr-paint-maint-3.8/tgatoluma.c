/* -*- c -*- */
/* 
 * Copyright 2015 Ron Economos.
 * 
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this software; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street,
 * Boston, MA 02110-1301, USA.
 */

#include <stdio.h>
#include <stdlib.h>

#define    TRUE        1
#define    FALSE       0

int main(int argc, char **argv)
{
    FILE    *fp;
    FILE    *fpout;
    int    length, i, j, horz, vert, index = 0;
    int    vertical_flip = TRUE;
    int    black_white;
    int    image_ident;
    int    bits_pixel;
    int    r, g, b, alpha;
    double    y;
    double    cr, cg, cb;
    unsigned char    *yp;
    int    matrix_coefficients = 1;
    static unsigned char    buffer_header[18];
    unsigned char    *buffer_ident;
    unsigned char    *buffer_444Y;
    unsigned char    *buffer_444input;
    static double coef[8][3] = {
        {0.2126, 0.7152, 0.0722},   /* ITU-R Rec. 709 */
        {0.299, 0.587, 0.114},      /* unspecified */
        {0.299, 0.587, 0.114},      /* reserved */
        {0.30,  0.59,  0.11},       /* FCC */
        {0.299, 0.587, 0.114},      /* ITU-R Rec. 624-4 System B, G */
        {0.299, 0.587, 0.114},      /* SMPTE 170M */
        {0.212, 0.701, 0.087},      /* SMPTE 240M (1987) */
        {0.2627, 0.678, 0.0593}};   /* ITU-R BT.2020-1 */

    if (argc != 3) {
        fprintf(stderr, "usage: tgatoluma <infile> <outfile>\n");
        exit(-1);
    }

    /*--- open binary file (for reading) ---*/
    fp = fopen(argv[1], "rb");
    if (fp == 0) {
        fprintf(stderr, "Cannot open input file <%s>\n", argv[1]);
        exit(-1);
    }

    /*--- open binary file (for writing) ---*/
    fpout = fopen(argv[2], "wb");
    if (fpout == 0) {
        fprintf(stderr, "Cannot open output file <%s>\n", argv[2]);
        exit(-1);
    }

    length = fread(&buffer_header[0], 1, 18, fp);
    if (length != 18) {
        fprintf(stderr, "Length Error reading input file <%s>\n", argv[1]);
        exit(-1);
    }

    image_ident = buffer_header[0];
    bits_pixel = buffer_header[16];

    horz = buffer_header[13] << 8;
    horz |= buffer_header[12];
    vert = buffer_header[15] << 8;
    vert |= buffer_header[14];
    printf("horz = %d, vert = %d\n", horz, vert);

    if (buffer_header[17] & 0x20)
    {
        vertical_flip = FALSE;
    }

    if (image_ident != 0) {
        buffer_ident = (unsigned char *)malloc(image_ident);
        length = fread(&buffer_ident[0], 1, image_ident, fp);
        if (length != image_ident) {
            free(buffer_ident);
            fprintf(stderr, "Length Error reading input file <%s>\n", argv[1]);
            exit(-1);
        }
        free(buffer_ident);
    }

    if (buffer_header[2] == 0x3)
    {
        black_white = TRUE;
        buffer_444input = (unsigned char *)malloc(horz * vert);
        length = fread(&buffer_444input[0], 1, (horz * vert), fp);
        if (length != (horz * vert)) {
            free(buffer_444input);
            fprintf(stderr, "Length Error reading input file <%s>\n", argv[1]);
            exit(-1);
        }
    }
    else
    {
        black_white = FALSE;
        if (bits_pixel == 32) {
            buffer_444input = (unsigned char *)malloc(horz * vert * 4);
            length = fread(&buffer_444input[0], 1, (horz * vert * 4), fp);
            if (length != (horz * vert * 4)) {
                free(buffer_444input);
                fprintf(stderr, "Length Error reading input file <%s>\n", argv[1]);
                exit(-1);
            }
        }
        else {
            buffer_444input = (unsigned char *)malloc(horz * vert * 3);
            length = fread(&buffer_444input[0], 1, (horz * vert * 3), fp);
            if (length != (horz * vert * 3)) {
                free(buffer_444input);
                fprintf(stderr, "Length Error reading input file <%s>\n", argv[1]);
                exit(-1);
            }
        }
    }

    buffer_444Y = (unsigned char *)malloc(horz * vert);

    i = matrix_coefficients;
    cr = coef[i-1][0];
    cg = coef[i-1][1];
    cb = coef[i-1][2];

    if (black_white == TRUE)
    {
        if (vertical_flip == FALSE)
        {
            index = 0;
        }
        else
        {
            index = (horz * (vert - 1));
        }

        for (i = 0; i < vert; i++)
        {
            yp = &buffer_444Y[0] + i * horz;

            for (j = 0 ; j < horz; j++)
            {
                /* convert to Y */
                y = buffer_444input[index++];
                yp[j] = (219.0 / 255.0) * y + 16.5;  /* nominal range: 16..235 */
            }
            if (vertical_flip)
            {
                index = index - (horz * 2);
            }
        }
    }
    else
    {
        if (vertical_flip == FALSE)
        {
            index = 0;
        }
        else
        {
            if (bits_pixel == 32) {
                index = ((horz * (vert - 1)) * 4);
            }
            else {
                index = ((horz * (vert - 1)) * 3);
            }
        }

        for (i = 0; i < vert; i++)
        {
            yp = &buffer_444Y[0] + i * horz;

            for (j = 0 ; j < horz; j++)
            {
                b = buffer_444input[index++];
                g = buffer_444input[index++];
                r = buffer_444input[index++];
                if (bits_pixel == 32) {
                    alpha = buffer_444input[index++];
                    if (alpha == 0) {
                        r = g = b = 235;
                    }
                }

                /* convert to Y */
                y = cr * r + cg * g + cb * b;
                yp[j] = (219.0 / 255.0) * y + 16.5;  /* nominal range: 16..235 */
            }
            if (vertical_flip)
            {
                if (bits_pixel == 32) {
                    index = index - (horz * 8);
                }
                else {
                    index = index - (horz * 6);
                }
            }
        }
    }
    fwrite(&buffer_444Y[0], 1, (horz * vert), fpout);
    free(buffer_444Y);
    free(buffer_444input);
    fclose(fp);
    fclose(fpout);
    return 0;
}

