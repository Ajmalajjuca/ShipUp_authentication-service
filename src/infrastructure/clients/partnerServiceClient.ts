import axios from 'axios';

export class PartnerServiceClient {
  private partnerServiceUrl: string;

  constructor(partnerServiceUrl: string = process.env.PARTNER_SERVICE_URL || '') {
    this.partnerServiceUrl = partnerServiceUrl;
  }

  async getDriverDetails(partnerId: string): Promise<any> {
    try {
      const response = await axios.get(
        `${this.partnerServiceUrl}/drivers/${partnerId}`
      );
      
      return response.data.partner;
    } catch (error: any) {
      console.error('Error fetching driver details:', {
        message: error.message,
        response: error.response?.data,
        status: error.response?.status,
        partnerId,
        serviceUrl: this.partnerServiceUrl
      });
      throw new Error(error.response?.data?.error || 'Failed to fetch driver details');
    }
  }

  async checkDriverStatus(partnerId: string): Promise<boolean> {
    try {
      const driver = await this.getDriverDetails(partnerId);
      return driver?.status || false;
    } catch (error) {
      console.error('Error checking driver status:', error);
      throw error;
    }
  }
} 