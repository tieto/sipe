/**
 * @file sipe-ft-tftp.h
 *
 * pidgin-sipe
 *
 * Copyright (C) 2014-2015 SIPE Project <http://sipe.sourceforge.net/>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

void
sipe_ft_tftp_start_receiving(struct sipe_file_transfer *ft, gsize total_size);

gboolean
sipe_ft_tftp_stop_receiving(struct sipe_file_transfer *ft);

gssize
sipe_ft_tftp_read(struct sipe_file_transfer *ft, guchar **buffer,
		  gsize bytes_remaining, gsize bytes_available);

void
sipe_ft_tftp_start_sending(struct sipe_file_transfer *ft, gsize total_size);

gboolean
sipe_ft_tftp_stop_sending(struct sipe_file_transfer *ft);

gssize
sipe_ft_tftp_write(struct sipe_file_transfer *ft, const guchar *buffer,
		   gsize size);
